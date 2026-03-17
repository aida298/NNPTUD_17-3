var express = require("express");
var router = express.Router();
let { CreateUserValidator, validationResult } = require('../utils/validatorHandler')
let userModel = require("../schemas/users");
let userController = require('../controllers/users')
let { CheckLogin } = require('../utils/authHandler')
let bcrypt = require('bcrypt'); // Cần bcrypt để hash pass mới

// 1. Lấy danh sách user (Yêu cầu đăng nhập)
router.get("/", CheckLogin, async function (req, res, next) {
    let users = await userModel
        .find({ isDeleted: false })
        .populate({
            path: 'role',
            select: 'name'
        })
    res.send(users);
});

// 2. Chức năng /me: Lấy thông tin của chính người đang đăng nhập
// Đây là route bạn cần chụp ảnh Postman
router.get("/me", CheckLogin, async function (req, res, next) {
    // req.user đã được CheckLogin gán vào sau khi verify token thành công
    res.send(req.user);
});

// 3. Chức năng Change Password (Yêu cầu đăng nhập)
router.post("/change-password", CheckLogin, async function (req, res, next) {
    try {
        const { oldPassword, newPassword } = req.body;
        const user = req.user;

        // Validate mật khẩu mới (Ít nhất 6 ký tự)
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).send({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
        }

        // Kiểm tra mật khẩu cũ có khớp không
        const isMatch = bcrypt.compareSync(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).send({ message: "Mật khẩu cũ không chính xác" });
        }

        // Hash mật khẩu mới và cập nhật vào Database
        const salt = bcrypt.genSaltSync(10);
        const hashedPass = bcrypt.hashSync(newPassword, salt);
        
        await userController.UpdatePassword(user._id, hashedPass);
        
        res.send({ message: "Đổi mật khẩu thành công!" });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

// 4. Lấy chi tiết 1 user theo ID
router.get("/:id", async function (req, res, next) {
    try {
        let result = await userModel
            .find({ _id: req.params.id, isDeleted: false })
        if (result.length > 0) {
            res.send(result);
        }
        else {
            res.status(404).send({ message: "id not found" });
        }
    } catch (error) {
        res.status(404).send({ message: "id not found" });
    }
});

// 5. Tạo user mới
router.post("/", CreateUserValidator, validationResult, async function (req, res, next) {
    try {
        let newItem = await userController.CreateAnUser(
            req.body.username, req.body.password, req.body.email, req.body.role
        )
        res.send(newItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

// 6. Cập nhật thông tin user
router.put("/:id", async function (req, res, next) {
    try {
        let id = req.params.id;
        let updatedItem = await
            userModel.findByIdAndUpdate(id, req.body, { new: true });

        if (!updatedItem) return res.status(404).send({ message: "id not found" });

        let populated = await userModel
            .findById(updatedItem._id)
        res.send(populated);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

// 7. Xóa user (Xóa mềm)
router.delete("/:id", async function (req, res, next) {
    try {
        let id = req.params.id;
        let updatedItem = await userModel.findByIdAndUpdate(
            id,
            { isDeleted: true },
            { new: true }
        );
        if (!updatedItem) {
            return res.status(404).send({ message: "id not found" });
        }
        res.send(updatedItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

module.exports = router;