const express = require('express');
const { body } = require('express-validator');
const {
  register,
  login,
  logout,
  getMe,
  refreshToken,
  forgotPassword,
  resetPassword,
  changePassword
} = require('../controllers/authController');
const { protect } = require('../middlewares/authMiddleware');

const router = express.Router();

// Validation rules
const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be between 3 and 20 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
];

const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

const passwordValidation = [
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
];

// Public routes
router.post('/register', registerValidation, register);
router.post('/login', loginValidation, login);
router.post('/refresh', refreshToken);
router.post('/forgot-password', [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email')
], forgotPassword);
router.post('/reset-password', [
  body('token').notEmpty().withMessage('Reset token is required'),
  ...passwordValidation
], resetPassword);

// Protected routes
router.use(protect); // Apply authentication middleware to all routes below

router.post('/logout', logout);
router.get('/me', getMe);
router.post('/change-password', [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long')
], changePassword);

module.exports = router;
