let userModel = require("../schemas/users");
let bcrypt = require('bcrypt');

module.exports = {
    // 1. Tạo User mới
    CreateAnUser: async function (username, password, email, role,
        fullName, avatarUrl, status, loginCount
    ) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullName,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        })
        await newUser.save();
        return newUser;
    },

    // 2. Tìm User theo Username
    FindUserByUsername: async function (username) {
        return await userModel.findOne({
            isDeleted: false,
            username: username
        })
    },

    // 3. Kiểm tra đăng nhập và xử lý khóa tài khoản
    CompareLogin: async function (user, password) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            return user;
        }
        user.loginCount++;
        if (user.loginCount >= 3) {
            // Khóa tài khoản 24h nếu sai 3 lần
            user.lockTime = new Date(Date.now() + 24 * 60 * 60 * 1000);
            user.loginCount = 0;
        }
        await user.save()
        return false;
    },

    // 4. Lấy thông tin User theo ID (Dùng cho chức năng /me)
    GetUserById: async function (id) {
        try {
            let user = await userModel.findOne({
                _id: id,
                isDeleted: false
            })
            return user;
        } catch (error) {
            return false;
        }
    },

    // 5. Hàm cập nhật mật khẩu mới (Bổ sung để làm chức năng Change Password)
    UpdatePassword: async function (id, newHashedPassword) {
        try {
            return await userModel.findByIdAndUpdate(id, {
                password: newHashedPassword
            }, { new: true });
        } catch (error) {
            return false;
        }
    }
}