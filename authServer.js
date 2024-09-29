//authServer.js
const express = require('express');
const corsOptions = require('./corsOptions');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const authRoutes = require('./authServerRoutes');
const authServer = express();

authServer.use(cors(corsOptions));
authServer.options('*', cors(corsOptions));
authServer.use(bodyParser.json());
authServer.use(cookieParser());
authServer.use('/api/auth', authRoutes);

const PORT = process.env.AUTH_SERVER_PORT || 8801;
authServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Auth server is running on port ${PORT}`);
});