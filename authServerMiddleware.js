// authServerMiddleware.js
const User = require('../server/models/users');
const jwt = require('jsonwebtoken');
const {generateToken, sendVerificationLink} = require("./authServerControllers");
const path = require('path');
require('dotenv').config({ path: path.resolve(process.cwd(), '.env') });

const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;

exports.authenticateToken = async (req, res, next) => {
    try {
        const token = req.cookies.accessToken;
        if (!token) {
            console.log('No access token provided');
            return res.sendStatus(401);
        }
        jwt.verify(token, accessTokenSecret, (err, user) => {
            if (err) {
                console.log('Access token not valid');
                return res.sendStatus(403);
            }
            console.log('Access is ok');
            req.user = user;
            next();
        });
    } catch (e) {
        console.log('Access caught error:', e);
        return res.sendStatus(404);
    }
};

exports.isAdmin = async (req, res, next) => {
    try {
        const userInfo = await User.findById(req.user.userID);
        if (!userInfo || userInfo.userType !== 'admin') {
            console.log('Admin info not valid');
            return res.sendStatus(403);
        }
        next();
    } catch (e) {
        console.error('Admin check error:', e);
        return res.sendStatus(500);
    }
};

exports.isVerified = async (req, res, next) => {
    try {
        const { emailAddress } = req.body;
        const user = await User.findByEmail(emailAddress);
        if (!user) {
            return res.status(404).json({ error: 'User not found.', errorType: 'user_not_found' });
        }
        const isVerified = await User.isEmailVerified(emailAddress);
        if (!isVerified) {
            const userData = {
                userID: user.userID,
                emailAddress,
            };
            const token = await generateToken(userData, process.env.EMAIL_TOKEN_SECRET, '30m');
            const linkSent = await sendVerificationLink(token, emailAddress);
            if (!linkSent) {
                return res.status(500).json({ error: 'Failed to send verification link.', errorType: 'email_send_failure' });
            }
            return res.status(401).json({ error: 'Account not verified. Please check your email for verification link.', errorType: 'verification_required' });
        }
        next();
    } catch (e) {
        console.error('Verification error:', e);
        return res.status(500).json({ error: 'Internal server error', errorType: 'internal_error' });
    }
};
