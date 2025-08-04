import jwt from 'jsonwebtoken';

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;
    console.log('Cookies:', req.cookies); // ✅ Already there

    if (!token) {
        return res.json({ success: false, message: 'Not Authorised, Login Again' });
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded User ID:', tokenDecode.id); // ✅ NEW LINE

        if (tokenDecode.id) {
            req.userId = tokenDecode.id;  // ✅ This gets passed to sendVerifyOTP
            next();
        } else {
            return res.json({ success: false, message: 'Not Authorised, Login Again' });
        }
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
};

export default userAuth;
