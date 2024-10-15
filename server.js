import express from 'express';
import multer from 'multer';
import path from 'path';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';
import retry from 'async-retry';
import admin from 'firebase-admin';
import { getStorage } from 'firebase-admin/storage';
import FormData from 'form-data'; // Ensure form-data is imported
import fs from 'fs';  // To load serviceAccount.json

// Initialize dotenv for environment variables
config();

// Initialize Firebase Admin SDK using require or fs to read JSON
const serviceAccount = JSON.parse(fs.readFileSync('./safescanx-firebase-adminsdk-i6wj4-f16b80d4b2.json', 'utf8'));
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://malware-2226.firebaseio.com",
    storageBucket: "gs://safescanx.appspot.com"  // Use your actual storage bucket
});

// Firestore Database reference
const db = admin.firestore();
// Firebase Storage reference
const storage = getStorage();

// Express app initialization
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = 3000;

const API_KEY = process.env.API_KEY;  // VirusTotal API Key from .env

// Serve static files like HTML, JS, and CSS
app.use(express.static(path.join(__dirname, 'src')));

// Middleware to handle JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Multer for handling file uploads (in memory storage)
const storageMulter = multer.memoryStorage(); // Use memory storage
const upload = multer({ storage: storageMulter });

// Max file size (32MB) for VirusTotal Free API
const MAX_FILE_SIZE = 32 * 1024 * 1024;

// Function to make API request to VirusTotal for URL scan
async function scanUrlWithVirusTotal(url) {
    return await retry(async bail => {
        const response = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${API_KEY}&resource=${url}`);
        if (!response.ok) throw new Error(`Failed to scan URL: ${response.status}`);
        const data = await response.json();
        return data;
    }, { retries: 3 });
}

// Function to make API request to VirusTotal for file scan
async function scanFileWithVirusTotal(fileBuffer, fileName) {
    return await retry(async bail => {
        // Create a FormData instance and append the file buffer directly
        const formData = new FormData();
        formData.append('file', fileBuffer, fileName);

        // Use node-fetch to post the file to VirusTotal API
        const response = await fetch(`https://www.virustotal.com/vtapi/v2/file/scan?apikey=${API_KEY}`, {
            method: 'POST',
            body: formData,
            headers: formData.getHeaders() // Important to include form data headers
        });

        if (!response.ok) throw new Error(`Failed to scan file: ${response.status}`);
        const data = await response.json();
        return data;
    }, { retries: 3 });
}

// API to handle URL scanning
app.post('/scan-url', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        const result = await scanUrlWithVirusTotal(url);
        const combinedResult = (result.positives / result.total) * 100;  // Malware percentage based on API response

        // Get user IP address
        const userIp = req.ip;

        // Save result to Firebase Firestore
        await db.collection('scans').add({
            url,
            combinedResult,
            userIp,  // Store the user's IP address
            scannedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ combinedResult, userIp });
    } catch (error) {
        console.error('Error scanning URL:', error);
        res.status(500).json({ error: 'Error scanning URL' });
    }
});

// API to handle file scanning and upload to Firebase Storage
app.post('/scan-file', upload.single('file'), async (req, res) => {
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: 'File is required' });
    }

    // Check if file exceeds the VirusTotal free tier file size limit
    if (file.size > MAX_FILE_SIZE) {
        return res.status(400).json({ error: 'File is too large to scan. Max file size is 32MB.' });
    }

    try {
        // Create a unique file path in Firebase Storage
        const filePath = `uploads/${file.originalname}`;

        // Upload file to Firebase Storage
        const bucket = storage.bucket();
        const fileUpload = bucket.file(filePath);

        await fileUpload.save(file.buffer, { // Save buffer directly
            metadata: {
                contentType: file.mimetype,
            },
        });

        // Get the src URL of the uploaded file
        const srcUrl = `https://storage.googleapis.com/${bucket.name}/${filePath}`;

        // Scan the file with VirusTotal
        const result = await scanFileWithVirusTotal(file.buffer, file.originalname);

        // Check if result contains expected values
        const positives = result.positives ?? 0;  // Default to 0 if undefined
        const total = result.total ?? 1;  // Default to 1 to avoid division by zero

        const combinedResult = (positives / total) * 100;  // Malware percentage based on API response

        // Get user IP address
        const userIp = req.ip;

        // Save result to Firebase Firestore
        await db.collection('scans').add({
            fileName: file.originalname,
            combinedResult,
            fileUrl: srcUrl,  // Store the URL of the file in Firebase Storage
            userIp,  // Store the user's IP address
            scannedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ combinedResult, fileUrl: srcUrl, userIp });
    } catch (error) {
        console.error('Error scanning file or uploading to Firebase:', error);
        res.status(500).json({ error: 'Error scanning file or uploading to Firebase' });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
