// authServerRoutes.js
const express = require('express');
const auth = express.Router();
const {
    login,
    logout,
    register,
    verifyEmail,
} = require('./authServerControllers');
const { getUserInfo } = require('../server/controllers/users');
const { authenticateToken, isVerified } = require('./authServerMiddleware');

/**
 * @route POST /api/auth/register
 * @description Register new user
 * @access Public
 */
auth.post('/register', register);

/**
 * @route POST /api/auth/login
 * @description Authenticate user credentials
 * @access Public
 */
auth.post('/login', isVerified, login);

/**
 * @route GET /api/auth/validateAccess
 * @description Authenticate user session
 * @access Public
 */
auth.get('/validateAccess', authenticateToken, getUserInfo);

/**
 * @route GET /api/auth/verify/:token
 * @description Accepts token to verify email
 * @access Public
 */
auth.get('/verify/:token', verifyEmail);

/**
 * @route DELETE /api/auth/logout
 * @description Logout user
 * @access Public
 */
auth.delete('/logout', logout);

module.exports = auth;