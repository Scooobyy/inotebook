const express = require('express');
const User = require('../models/User');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'Pranavisagoodboi';

// Route to create a new user
router.post('/createuser', 
  [
    body('name', 'Enter a valid name').isLength({ min: 3 }),
    body('email', 'Enter a valid email').isEmail(),
    body('password').isLength({ min: 5 }),
  ], 
  async (req, res) => {

    // If there are errors return bad request 
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Check whether the user with email exists already   
    let user = await User.findOne({ email: req.body.email });
    console.log('User found in DB:', user);

    if (user) {
      return res.status(400).json({ error: "Sorry, the user with this email already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const secPass = await bcrypt.hash(req.body.password, salt);

    // Create a new user
    user = await User.create({
      name: req.body.name,
      password: secPass,
      email: req.body.email,
    });

    const data = {
      user: {
        id: user.id,
      },
    };

    const authtoken = jwt.sign(data, JWT_SECRET);

    res.json({ authtoken });
  }
);

// Route to login an existing user
router.post('/login', 
  [
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password is required').exists(),
  ], 
  async (req, res) => {

    // If there are errors return bad request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Check if the user exists
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Compare the password with the one in the database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const data = {
      user: {
        id: user.id,
      },
    };

    // Generate the JWT token
    const authtoken = jwt.sign(data, JWT_SECRET);

    res.json({ authtoken });
  }
);

module.exports = router;
