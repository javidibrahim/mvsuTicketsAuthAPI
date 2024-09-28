// authServer/authController.js
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config({ path: path.resolve(process.cwd(), '.env') });
const axios = require('axios');

const BackEndURL = process.env.BACKEND_URL;
const refreshTokenSecret = process.env.ACCESS_TOKEN_REFRESH;
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const emailTokenSecret = process.env.EMAIL_TOKEN_SECRET;
const baseFrontURL = process.env.BASE_FRONT_URL;


/**
 * @description getUserInfo fetch user information from backend after authentication
 * @access Public
 */
exports.getUserInfo = async (req, res) => {
  try {
    // Now using the user ID from the `req.user` object set by authenticateToken
    const response = await axios.get(`${BackEndURL}/user/profile`, {
      params: {
        userID: req.user.userID,
      }
    });
    res.status(200).json(response.data);
  } catch (error) {
    console.error('Error fetching user info from backend:', error.message);
    res.status(500).json({ error: 'Failed to validate user session' });
  }
};

exports.login = async (req, res) => {
  const { emailAddress, password } = req.body;
  try {
    const response = await axios.post(`${BackEndURL}/user/login`, {emailAddress, password});
    const { userID, userType } = response.data;
    if (!userID) {
      return res.status(401).json({ error: 'Email or password is incorrect.', errorType: 'invalid_credentials' });
    }

    const userData = { userID, emailAddress, userType };
    const accessToken = await generateToken(userData, accessTokenSecret, '30m');
    const refreshToken = await generateToken(userData, refreshTokenSecret, '7d');
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000 * 0.5, // expires 30 minutes
      sameSite: 'None',
      secure: true,
      path: '/',
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000 * 24 * 7, // expires 7 days
      sameSite: 'None',
      secure: true,
      path: '/',
    });
    res.status(200).json({
      message: 'Logged in successfully',
      user: { userType: userData.userType}
    });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.register = async (req, res) => {
  const { firstName, lastName, emailAddress, password, phoneNumber} = req.body;
  try {
    const userData = { firstName, lastName, emailAddress, password, phoneNumber };
    const response = await axios.post(`${BackEndURL}/user/register`, {userData});
    const {userID} = response.data;
    if (!userID) {
      return res.status(500).json({ error: 'registration_error' });
    }
    const user = {
      userID: userID,
      emailAddress: req.body.emailAddress,
    };
    const token = await generateToken(user, emailTokenSecret, '30m');
    const linkSent = await sendVerificationLink(token, emailAddress);
    if (!linkSent) {
      return res.status(500).json({ error: 'verification_link_error' });
    }
    res.status(201).json({ message: 'success_verification_required' });
  } catch (e) {
    console.error('Registration error:', e);
    handleMySqlError(e, res);
  }
};

exports.logout = async (req, res) => {
  res.cookie('accessToken', '', { maxAge: 0 });
  res.cookie('refreshToken', '', { maxAge: 0 });
  res.status(200).json({ message: 'Logged out successfully' });
};

// Frontend - verifyEmail function
exports.verifyEmail = async (req, res) => {
  console.log('Verifying email...');
  let message, status = 'fail';
  try {
    const token = req.params.token;
    const decodedToken = jwt.verify(token, emailTokenSecret); // Verify the token
    const decodedEmail = decodedToken.emailAddress;

    const response = await axios.get(`${BackEndURL}/user/profile`, {
      params: {
        emailAddress: decodedEmail,
      }
    });

    const { userID, verified } = response.data;

    if (!userID) {
      message = 'No user found with this email.';
    } else if (verified) {
      message = 'User with this email has already been verified.';
    } else {
      const verifyResponse = await axios.put(`${BackEndURL}/user/verifyEmail`, {
        emailAddress: decodedEmail
      });

      if (!verifyResponse || verifyResponse.status !== 200) {
        message = 'Failed to verify the email.';
        status = 'fail';
      } else {
        message = 'Email has been verified successfully.';
        status = 'success';
      }
    }
  } catch (error) {
    console.error('Error during email verification:', error.message);
    message = 'Something went wrong during email verification.';
    status = 'fail';

    if (error.name === 'JsonWebTokenError') {
      message = 'Invalid token. Please request a new verification email.';
    } else if (error.name === 'TokenExpiredError') {
      message = 'Verification link has expired. Please request a new verification email.';
    }
  }

  return res.redirect(`${baseFrontURL}/verification-result?status=${status}&message=${encodeURIComponent(message)}`);
};


async function generateToken(payload, secretKey, expiresIn) {
  try {
    return jwt.sign(payload, secretKey, { expiresIn });
  } catch (e) {
    console.error('Token generation error:', e.message);
    throw e;
  }
}

exports.generateToken = generateToken;

async function sendVerificationLink(token, email) {
  try {
    const url = `${BackEndURL}/api/auth/verify/${token}`;
    const emailSubject = 'Verify your getValleyTickets account.';

    const emailContent = `
          <p>Hello,</p>
          <p>Please click the following link to verify your email:</p>
          <a href="${url}">Verify Email</a>
        `;
    const emailSent = axios.post(`${BackEndURL}/email/verify/sendVerification`, {
      email,
      emailSubject,
      emailContent,
    })
    if (emailSent.status !== 200) {
      console.log('Error sending verification link', emailSent);
      return false;
    }

    console.log(`Verification link sent to ${email}`);
    return true;
  } catch (e) {
    console.error('Error sending verification link:', e.message);
    return false;
  }
}
exports.sendVerificationLink = sendVerificationLink;

function handleMySqlError(error, res) {
  switch (error.code) {
    case 'ER_DUP_ENTRY':
      res.status(409).json({ message: 'Email already exists' });
      break;
    case 'ER_BAD_DB_ERROR':
      res.status(500).json({ message: 'Database not found' });
      break;
    case 'ER_PARSE_ERROR':
      res.status(400).json({ message: 'Query syntax error' });
      break;
    case 'ER_NO_REFERENCED_ROW':
    case 'ER_NO_REFERENCED_ROW_2':
      res.status(400).json({ message: 'Foreign key constraint fails' });
      break;
    case 'ER_DATA_TOO_LONG':
      res.status(400).json({ message: 'Data too long for column' });
      break;
    default:
      res.status(500).json({ message: 'Database error', error: error.sqlMessage });
  }
}