import express from 'express';
import {User} from "../module/User.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import dotenv from 'dotenv';
dotenv.config();

app.use(express.json());

const router = express.Router();

router.post('/SignUp', async (req, res) => {
    const {
        firstName, middleName, lastName,
        email, confirmEmail,
        password, confirmPassword,
        Address, Zipcode, PhoneNumber, Gender
    } = req.body;

    if (!email) return res.status(400).json({ error: "Email cannot be empty" });
    if (!confirmEmail) return res.status(400).json({ error: "Confirm Email cannot be empty" });
    if (password !== confirmPassword) return res.status(400).json({ error: "Passwords do not match" });

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: "Email already exists" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            firstname: firstName,
            middle: middleName,
            lastname: lastName,
            email:email,
            confirmEmail:confirmEmail,
            Address:Address,
            ZipCode: Zipcode,
            phoneNumber: PhoneNumber,
            Gender:Gender,
            password:password,
            confirmPassword:confirmPassword,
        });

        await newUser.save();
        res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        res.status(500).json({ error: "Server error", details: err.message });
    }
});

router.post('/Login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

        res.json({ message: "Login successful" });
    } catch (err) {
        res.status(500).json({ error: "Server error", details: err.message });
    }
});

router.post('/ForgotPassword', async (req, res) => {
            const { email } = req.body;
            try {
                const user = await User.findOne({ email });
                if (!user) {
                    return res.json({ message: "If that email exists, a reset link has been sent." });
                }
                const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
                const resetURL = `${process.env.CLIENT_URL}/ResetPassword/${resetToken}`;

                console.log("Reset URL:", resetURL);
                res.json({ message: "Reset link sent", resetURL });
            } catch (err) {
                res.status(500).json({ error: "Server error", details: err.message });
            }
        });

router.post('/ResetPassword/:token', async (req, res) => {
            const { token } = req.params;
            const { password, confirmPassword } = req.body;
            if (password !== confirmPassword) {
                return res.status(400).json({ error: "Passwords do not match" });
            }
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                const user = await User.findById(decoded.id);
                if (!user) return res.status(404).json({ error: "User not found" });
                const salt = await bcrypt.genSalt(10);
                const hashedPassword = await bcrypt.hash(password, salt);
                user.password = hashedPassword;
                user.confirmPassword = hashedPassword; // Assuming you want to keep this in sync
                await user.save();
                res.json({ message: "Password updated successfully" });
            } catch (err) {
                if (err.name === 'TokenExpiredError') {
                    return res.status(400).json({ error: "Reset link has expired" });
                }
                res.status(500).json({ error: "Server error", details: err.message });
            }
        });

export default router;