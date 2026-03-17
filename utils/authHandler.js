let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')

module.exports = {
    CheckLogin: async function (req, res, next) {
        // 1. Lấy token từ Header hoặc Cookie
        let key = req.headers.authorization;
        if (!key) {
            if (req.cookies.LOGIN_NNPTUD_S3) {
                key = req.cookies.LOGIN_NNPTUD_S3;
            } else {
                return res.status(401).json({ message: "Bạn chưa đăng nhập" });
            }
        }

        // Nếu token có chữ "Bearer ", chúng ta cần loại bỏ nó để lấy chuỗi JWT nguyên bản
        if (key.startsWith('Bearer ')) {
            key = key.slice(7, key.length);
        }

        try {
            // 2. Đọc file Public Key để xác thực (RS256 dùng Public Key để Verify)
            // Lưu ý: path.join giúp đảm bảo tìm đúng file public.pem ở thư mục gốc dự án
            const publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'), 'utf8');

            // 3. Thực hiện verify với thuật toán RS256
            let result = jwt.verify(key, publicKey, { algorithms: ['RS256'] });

            // 4. Kiểm tra user tồn tại trong hệ thống
            let user = await userController.GetUserById(result.id);
            if (!user) {
                return res.status(401).json({ message: "Người dùng không tồn tại hoặc đã bị xóa" });
            }

            // Gán thông tin user vào request để các hàm sau (như changePassword) sử dụng
            req.user = user;
            next();
        } catch (error) {
            // Nếu token sai, hết hạn hoặc key không khớp sẽ nhảy vào đây
            return res.status(401).json({ message: "Token không hợp lệ hoặc đã hết hạn" });
        }
    }
}