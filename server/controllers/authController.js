import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

export const register = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.json({ success: false, message: 'details missing' })
    }
    try {
        const existingUser = await userModel.findOne({ email })
        if (existingUser) {
            return res.json({ success: false, message: "user already exist" })
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword })
        await user.save()
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // corrected: should be milliseconds for 7 days
        })
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Hello ✔",
            text: `Welcome, Your account has been created successfully with email ${email}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Registration email error:', error);
                // Optionally, respond with success anyway, but warn client
                return res.json({ success: true, message: 'Registered, but failed to send email' });
            } else {
                console.log('Registration email sent:', info.response);
                return res.json({ success: true });
            }
        });

    } catch (error) {
        res.json({ success: false, message: error.message })
    }
}

export const login = async (req, res) => {
    const { email, password } = req.body
    if (!email || !password) {
        return res.json({ success: false, message: 'Email and password are required' })
    }
    try {
        const user = await userModel.findOne({ email })
        if (!user) {
            return res.json({ success: false, message: 'Invalid Email' })
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid Password' })
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })
        return res.json({ success: true })
    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })
        return res.json({ success: true, message: 'logged out' })
    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

export const sendVerifyOTP = async (req, res) => {
    try {
        const userId = req.userId; // ✅ from middleware
        console.log('Decoded userId:', userId); // 🐛 debug log

        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: 'Account Already Verified' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email),
            headers: {
                'Content-Type': 'text/html; charset=UTF-8',
            },
        };


        // ✅ Using async/await version of sendMail
        const info = await transporter.sendMail(mailOptions);
        console.log('OTP email sent:', info.response);

        return res.json({ success: true, message: 'Verification OTP sent to your email' });

    } catch (error) {
        console.error('sendVerifyOTP error:', error.message);
        return res.json({ success: false, message: error.message });
    }
};
export const verifyEmail = async (req, res) => {
    const { otp } = req.body;
    const userId = req.userId; // from middleware
    if (!userId || !otp) {
        return res.json({ success: false, message: 'Missing Details' })
    }
    try {
        const user = await userModel.findById(userId)
        if (!user) {
            return res.json({ success: false, message: 'user not found' })
        }
        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' })
        }
        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP Expired' })
        }
        user.isAccountVerified = true
        user.verifyOtp = ''
        user.verifyOtpExpireAt = 0
        await user.save()
        return res.json({ success: true, message: 'Email verified successfully' })
    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}
export const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true })
    } catch (error) {
        res.json({ success: false, message: error.message })
    }
}
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ success: false, message: 'Email is required' });
    }

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email),
            headers: {
                'Content-Type': 'text/html; charset=UTF-8',
            },
        };


        const info = await transporter.sendMail(mailOptions);
        console.log('OTP email sent:', info.response);
        console.log('sendResetOtp route hit');

        return res.json({ success: true, message: 'OTP sent to your email' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body
    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: 'Email, OTP and New Password are required' })
    }
    try {
        const user = await userModel.findOne({ email })
        if (!user) {
            return res.json({ success: false, message: 'User not Found' })
        }
        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' })
        }
        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP expired' })
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10)
        user.password = hashedPassword
        user.resetOtp = ''
        user.resetOtpExpireAt = 0
        await user.save()
        return res.json({ success: true, message: 'Password has been reset successfully' })
    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

