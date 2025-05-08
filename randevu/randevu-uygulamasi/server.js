const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// MySQL bağlantısı
const db = mysql.createConnection({
    host: 'localhost',
    user: 'admin36',
    password: 'Qq4209@',
    database: 'randevu'
});

// MySQL bağlantısı
db.connect(err => {
    if (err) {
        console.error('MySQL bağlantısı başarısız:', err);
        return;
    }
    console.log('MySQL bağlandı');
});

// Middleware for token authentication
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.sendStatus(401); // Token yoksa 401 hatası döndür

    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret', (err, user) => { // Secret anahtarını çevre değişkeninden al
        if (err) return res.sendStatus(403); // Geçersiz token için 403 hatası döndür
        req.user = user; // Kullanıcıyı isteğe ekle
        next();
    });
}

// Kayıt API
app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;

    // E-posta kontrolü
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) {
            return res.status(400).send(err);
        }
        if (results.length > 0) {
            return res.status(400).send({ message: 'Zaten var olan bir hesabınız var.' });
        }

        const hashedPassword = bcrypt.hashSync(password, 10); // Şifreyi hashle
        const insertSql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
        db.query(insertSql, [name, email, hashedPassword], (err, results) => {
            if (err) {
                return res.status(400).send(err);
            }
            res.status(201).send({ message: 'Kayıt başarılı!' });
        });
    });
});

// Giriş API
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).send({ success: false, message: 'Kullanıcı bulunamadı! veya Şifre yanlış!' });
        }

        const user = results[0];
        const isMatch = bcrypt.compareSync(password, user.password); // Şifre karşılaştırması

        if (!isMatch) {
            return res.status(400).send({ success: false, message: 'Kullanıcı bulunamadı! veya Şifre yanlış!' });
        }

        const token = jwt.sign({ id: user.id, email: user.email, name: user.name, surname: user.surname }, process.env.JWT_SECRET || 'your_jwt_secret'); // Token oluştur

        // Kullanıcı adı ve soyadını da yanıtla
        res.send({
            success: true,
            token,
            name: user.name,
            surname: user.surname
        });
    });
});

// Randevu alma API
app.post('/api/appointments', authenticateToken, (req, res) => {
    const { name, surname, phone, date, time, message, style } = req.body;

    // Gerekli alanların kontrolü
    if (!name || !surname || !phone || !date || !time) {
        return res.status(400).send({ message: 'Tüm alanlar gereklidir.' });
    }

    const userId = req.user.id; // Giriş yapan kullanıcının ID'si

    // Randevu limit kontrolü
    const checkSql = 'SELECT COUNT(*) AS count FROM appointments WHERE date = ? AND time = ?';
    db.query(checkSql, [date, time], (err, results) => {
        if (err) {
            console.error('Randevu limit kontrol hatası:', err);
            return res.status(500).send({ message: 'Veritabanı hatası.' });
        }

        const count = results[0].count;
        if (count >= 3) {
            return res.status(400).send({ message: 'Bu saatteki randevu limiti dolmuştur.' });
        }

        // Randevu kaydetme
        const sql = 'INSERT INTO appointments (user_id, name, surname, phone, date, time, message, style) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        db.query(sql, [userId, name, surname, phone, date, time, message, style], (err, results) => {
            if (err) {
                console.error('Randevu kaydetme hatası:', err);
                return res.status(400).send(err);
            }
            res.status(201).send({ message: 'Randevu alındı!', appointmentId: results.insertId });
        });
    });
});

// Randevuları getir
app.get('/api/appointments', authenticateToken, (req, res) => {
    const userId = req.user.id; // Token'dan kullanıcıyı al
    const sql = 'SELECT * FROM appointments WHERE user_id = ?'; // Sadece bu kullanıcıya ait randevuları getir

    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error('Randevuları getirirken hata:', err);
            return res.status(500).send(err);
        }

        // Randevu verilerini formatla
        const formattedResults = results.map(appointment => {
            const date = new Date(appointment.date);
            const formattedDate = `${date.getDate().toString().padStart(2, '0')}.${(date.getMonth() + 1).toString().padStart(2, '0')}.${date.getFullYear()}`; // 31.12.2024 formatı
            const formattedTime = appointment.time.slice(0, 5); // 11:00 formatı
            return {
                id: appointment.id,
                date: formattedDate,
                time: formattedTime,
                name: `${appointment.name || ''} ${appointment.surname || ''}`.trim(), // 'undefined' eklenmesini önlemek için
            };
        });

        res.send(formattedResults);
    });
});

// Randevu iptali
app.delete('/api/appointments/:id', authenticateToken, (req, res) => {
    const sql = 'DELETE FROM appointments WHERE id = ? AND user_id = ?';
    db.query(sql, [req.params.id, req.user.id], (err, results) => {
        if (err) {
            console.error('Randevu iptali hatası:', err);
            return res.status(500).send(err);
        }
        if (results.affectedRows === 0) {
            return res.status(404).send({ message: 'Randevu bulunamadı veya izin yok.' });
        }
        res.send({ message: 'Randevu iptal edildi.' });
    });
});

// Geri bildirim gönderme API
app.post('/api/feedback', authenticateToken, (req, res) => {
    const { name, rating, comment } = req.body;

    // Gerekli alanların kontrolü
    if (!name || !rating || !comment) {
        return res.status(400).send({ message: 'Tüm alanlar gereklidir.' });
    }

    const sql = 'INSERT INTO feedback (name, rating, comments) VALUES (?, ?, ?)';
    db.query(sql, [name, rating, comment], (err, results) => {
        if (err) {
            return res.status(400).send(err);
        }
        res.status(201).send({ message: 'Geri bildirim gönderildi!' });
    });
});

// Geri bildirimleri getir API
app.get('/api/feedback', (req, res) => {
    const sql = 'SELECT * FROM feedback ORDER BY id DESC'; // Geri bildirimleri ID'ye göre azalan sıralar
    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        // Geri bildirim verilerini döndür
        res.send(results); 
    });
});




// Middleware for admin authentication
function authenticateAdmin(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret', (err, admin) => {
        if (err) return res.sendStatus(403);
        req.admin = admin;
        next();
    });
}


app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;

    const sql = 'SELECT * FROM admins WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) {
            console.error('Veritabanı hatası:', err);
            return res.status(500).send({ success: false, message: 'Veritabanı hatası!' });
        }
        if (results.length === 0) {
            return res.status(400).send({ success: false, message: 'Kullanıcı bulunamadı! veya Şifre yanlış!' });
        }

        const admin = results[0];
        const isMatch = bcrypt.compareSync(password, admin.password);

        if (!isMatch) {
            return res.status(400).send({ success: false, message: 'Kullanıcı bulunamadı! veya Şifre yanlış!' });
        }

        const token = jwt.sign({ id: admin.id, username: admin.username }, process.env.JWT_SECRET || 'your_jwt_secret');
        res.send({ success: true, token, username: admin.username });
    });
});

// Kullanıcıları listeleme
app.get('/api/users', authenticateAdmin, (req, res) => {
    const sql = 'SELECT id, name, email FROM users';
    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.send(results);
    });
});

// Kullanıcı silme
app.delete('/api/users/:id', authenticateAdmin, (req, res) => {
    const sql = 'DELETE FROM users WHERE id = ?';
    db.query(sql, [req.params.id], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.send({ message: 'Kullanıcı silindi.' });
    });
});

// Yönetici randevuları listeleme
app.get('/api/appointment', authenticateAdmin, (req, res) => {
    const sql = `
        SELECT 
            id, 
            user_id, 
            name, 
            surname, 
            phone, 
            DATE_FORMAT(date, '%d.%m.%Y') AS formatted_date, 
            time, 
            message,
            style
        FROM 
            appointments
    `;

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Randevular alınırken hata:', err);
            return res.status(500).send({ message: 'Veritabanı hatası.' });
        }
        res.send(results);
    });
});



// Randevu silme
app.delete('/api/appointment/:id', authenticateAdmin, (req, res) => {
    const sql = 'DELETE FROM appointments WHERE id = ?';
    db.query(sql, [req.params.id], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.send({ message: 'Randevu silindi.' });
    });
});

// Geri bildirimleri listeleme
app.get('/api/feedback', authenticateAdmin, (req, res) => {
    const sql = 'SELECT id, name, rating, comments, created_at FROM feedback';
    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.send(results);
    });
});

// Geri bildirim silme
app.delete('/api/feedback/:id', authenticateAdmin, (req, res) => {
    const sql = 'DELETE FROM feedback WHERE id = ?';
    db.query(sql, [req.params.id], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.send({ message: 'Geri bildirim silindi.' });
    });
});


// Sunucuyu başlat
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
