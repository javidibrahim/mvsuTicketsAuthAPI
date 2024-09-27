const cors = require('cors');

// Define the CORS whitelist with exact URLs/IPs
const corsWhitelist = [
    'http://10.106.4.39:5173',
    'http://10.106.4.7:5173',
    'http://10.251.7.20:5173',
    'http://0.0.0.0:5173',
    process.env.FRONTEND_URL,
    process.env.ANOTHER_FRONTEND_URL,
    process.env.BACKEND_URL,
    process.env.ADMIN_API_URL,
];

// Define the CORS options
const corsOptions = {
    origin: function (origin, callback) {
        // Check if the origin is in the whitelist or if there's no origin (e.g., Postman)
        if (corsWhitelist.indexOf(origin) !== -1 || !origin) {
            callback(null, true);  // Allow the request
        } else {
            callback(new Error('Not allowed by CORS'));  // Block the request if not whitelisted
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
};

// Export the CORS options to be used across the app
module.exports = corsOptions;