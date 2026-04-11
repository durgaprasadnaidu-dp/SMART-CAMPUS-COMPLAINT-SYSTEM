// filepath: smart-campus-complaint-system/server/controllers/authController.js

const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Register a new user
const register = async (req, res) => {
    const { email, password, role, name, department } = req.body;

    try {
        // Validate required fields
        if (!email || !password || !role || !name || !department) {
            return res.status(400).json({ 
                message: 'All fields are required: email, password, role, name, department' 
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Please enter a valid email address' });
        }

        // Validate password length
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long' });
        }

        // Validate role
        if (!['student', 'staff'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role. Must be student or staff' });
        }

        // ✅ EMAIL DOMAIN VALIDATION
        if (role === 'student' && !email.endsWith('@vitapstudent.ac.in')) {
            return res.status(400).json({
                message: 'Student email must be @vitapstudent.ac.in'
            });
        }

        if (role === 'staff' && !email.endsWith('@vitap.ac.in')) {
            return res.status(400).json({
                message: 'Staff email must be @vitap.ac.in'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({
            email: email.trim(),
            password: hashedPassword,
            role,
            name: name.trim(),
            department: department.trim()
        });

        await newUser.save();
        console.log('User registered successfully:', { email, role, name, department });
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        if (error.code === 11000) {
            return res.status(400).json({ message: 'User with this email already exists' });
        }
        res.status(500).json({ message: 'Server error during registration' });
    }
};



const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // 🔍 check user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }

        // 🔐 check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        // 🎯 CREATE TOKEN (VERY IMPORTANT FIX)
        const token = jwt.sign(
            {
                id: user._id,
                role: user.role   // 🔥 THIS FIXES YOUR ADMIN ISSUE
            },
            process.env.JWT_SECRET || "secret123",
            { expiresIn: '1d' }
        );

        // ✅ SEND RESPONSE (YOU WERE MISSING THIS)
        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
    }
};



// Get user statistics (public)
const getUserStats = async (req, res) => {
    try {
        console.log('getUserStats called');
        
        const totalUsers = await User.countDocuments();
        console.log('Total users:', totalUsers);
        
        const studentCount = await User.countDocuments({ role: 'student' });
        console.log('Student count:', studentCount);
        
        const staffCount = await User.countDocuments({ role: 'staff' });
        console.log('Staff count:', staffCount);
        
        const stats = {
            total: totalUsers,
            students: studentCount,
            staff: staffCount
        };
        
        console.log('Returning user stats:', stats);
        res.json(stats);
    } catch (error) {
        console.error('Error in getUserStats:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

module.exports = { register, login, getUserStats };