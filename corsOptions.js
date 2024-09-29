const cors = require('cors');

// Define the CORS whitelist with exact URLs/IPs
const corsWhitelist = [
    'http://10.106.4.39:5173',
    'http://10.106.4.7:5173',
    'http://10.251.7.20:5173',
    'http://0.0.0.0:5173',
    process.env.BACKEND_URL,
    process.env.BACKEND_AUTH_URL,
    process.env.BACKEND_ADMIN_URL,
    process.env.FRONTEND_URL,
];

// Define the CORS options
const corsOptions = {
    origin: function (origin, callback) {
        // Log the origin for debugging purposes
        console.log(`CORS origin: ${origin}`);

        // Check if the origin is in the whitelist or if there's no origin (e.g., Postman or curl requests)
        if (corsWhitelist.indexOf(origin) !== -1 || !origin) {
            callback(null, true);  // Allow the request
        } else {
            console.log(`Blocked by CORS: ${origin}`);  // Log the blocked origin
            callback(new Error(`Not allowed by CORS: ${origin}`));  // Block the request if not whitelisted
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};

// Export the CORS options to be used across the app
module.exports = corsOptions;
