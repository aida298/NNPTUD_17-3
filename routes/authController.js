const changePassword = async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id; // Lấy từ middleware verify token

    // 1. Validate password mới (Ví dụ: ít nhất 6 ký tự)
    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ message: "Mật khẩu mới phải có ít nhất 6 ký tự!" });
    }

    // 2. Kiểm tra mật khẩu cũ có đúng không (sử dụng bcrypt để so sánh)
    const user = await User.findById(userId);
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: "Mật khẩu cũ không chính xác!" });
    }

    // 3. Hash mật khẩu mới và lưu
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.status(200).json({ message: "Đổi mật khẩu thành công!" });
};