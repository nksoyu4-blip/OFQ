const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || 'ofq-2024';

// ===== ЗАЩИТА =====
process.on('uncaughtException', (err) => {
    console.error('❌ Необработанное исключение:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Необработанный reject:', reason);
});

// ===== MIDDLEWARE =====
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// ===== ПАПКИ =====
const folders = ['uploads/avatars', 'uploads/posts', 'uploads/videos', 'uploads/comments', 'uploads/chat', 'uploads/voice'];
folders.forEach(d => {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ===== MULTER =====
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'avatar' || file.fieldname === 'banner') cb(null, 'uploads/avatars');
        else if (file.fieldname === 'commentFile') cb(null, 'uploads/comments');
        else if (file.fieldname === 'chatFile') cb(null, 'uploads/chat');
        else if (file.fieldname === 'voiceMessage') cb(null, 'uploads/voice');
        else if (file.mimetype && file.mimetype.startsWith('video/')) cb(null, 'uploads/videos');
        else cb(null, 'uploads/posts');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }
});

// ===== БАЗА ДАННЫХ =====
let db = { 
    users: [], 
    posts: [], 
    likes: [], 
    comments: [], 
    follows: [], 
    reports: [],
    reportsUser: [],
    blozdaMessages: [],
    pinnedPosts: [],
    blockedUsers: [],
    spamWarnings: []
};

function loadDB() {
    try {
        if (fs.existsSync('data.json')) {
            const data = fs.readFileSync('data.json', 'utf8');
            db = JSON.parse(data);
            // Проверяем что все поля есть
            if (!db.posts) db.posts = [];
            if (!db.users) db.users = [];
            if (!db.likes) db.likes = [];
            if (!db.comments) db.comments = [];
            if (!db.follows) db.follows = [];
            if (!db.reports) db.reports = [];
            if (!db.reportsUser) db.reportsUser = [];
            if (!db.blozdaMessages) db.blozdaMessages = [];
            if (!db.pinnedPosts) db.pinnedPosts = [];
            if (!db.blockedUsers) db.blockedUsers = [];
            console.log('✅ База загружена, постов:', db.posts.length);
        } else {
            const hash = bcrypt.hashSync('admin123', 10);
            db.users.push({
                id: 'admin-001',
                username: '1kz',
                email: 'admin@ofq.com',
                password: hash,
                avatar: '/default-avatar.png',
                banner: '/default-banner.png',
                bio: '👑 Администратор',
                isAdmin: true,
                isVerified: true,
                isBanned: false,
                banReason: '',
                banUntil: null,
                createdAt: new Date().toISOString()
            });
            saveDB();
            console.log('✅ Админ создан: 1kz / admin@ofq.com / admin123');
        }
    } catch (e) {
        console.error('❌ Ошибка загрузки БД:', e);
        saveDB();
    }
}

function saveDB() {
    try {
        fs.writeFileSync('data.json', JSON.stringify(db, null, 2));
    } catch (e) {
        console.error('❌ Ошибка сохранения БД:', e);
    }
}

loadDB();

// ===== АУТЕНТИФИКАЦИЯ =====
function auth(req, res, next) {
    let token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Не авторизован' });
    try {
        const decoded = jwt.verify(token, SECRET);
        const user = db.users.find(u => u.id === decoded.id);
        if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
        
        if (user.isBanned) {
            if (user.banUntil && new Date(user.banUntil) > new Date()) {
                return res.status(403).json({ 
                    error: `Вы забанены до ${new Date(user.banUntil).toLocaleDateString()}`,
                    banned: true,
                    banUntil: user.banUntil,
                    banReason: user.banReason
                });
            } else if (user.banUntil) {
                user.isBanned = false;
                user.banUntil = null;
                user.banReason = '';
                saveDB();
            }
        }
        
        req.user = user;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Неверный токен' });
    }
}

function adminAuth(req, res, next) {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Доступ запрещен' });
    next();
}

// ===== API МАРШРУТЫ =====

// ----- АУТЕНТИФИКАЦИЯ -----
app.post('/api/register', upload.fields([{ name: 'avatar', maxCount: 1 }, { name: 'banner', maxCount: 1 }]), async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: 'Все поля обязательны' });
        if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
        if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'Email занят' });
        if (db.users.find(u => u.username === username)) return res.status(400).json({ error: 'Имя занято' });

        const hash = await bcrypt.hash(password, 10);
        const avatar = req.files?.avatar ? `/uploads/avatars/${req.files.avatar[0].filename}` : '/default-avatar.png';
        const banner = req.files?.banner ? `/uploads/avatars/${req.files.banner[0].filename}` : '/default-banner.png';

        const user = {
            id: uuidv4(),
            username,
            email,
            password: hash,
            avatar,
            banner,
            bio: '',
            isAdmin: false,
            isVerified: true,
            isBanned: false,
            banReason: '',
            banUntil: null,
            createdAt: new Date().toISOString()
        };
        db.users.push(user);
        saveDB();

        const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '30d' });
        res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax', path: '/' });
        res.json({ success: true, token, user });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = db.users.find(u => u.email === email);
        if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });
        
        if (user.isBanned) {
            if (user.banUntil && new Date(user.banUntil) > new Date()) {
                return res.status(403).json({ 
                    error: `Вы забанены до ${new Date(user.banUntil).toLocaleDateString()}`,
                    banned: true,
                    banUntil: user.banUntil,
                    banReason: user.banReason
                });
            } else if (user.banUntil) {
                user.isBanned = false;
                user.banUntil = null;
                user.banReason = '';
                saveDB();
            }
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Неверный email или пароль' });

        const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '30d' });
        res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax', path: '/' });
        res.json({ success: true, token, user });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
    res.json({ user: req.user });
});

// ----- ПРОФИЛЬ -----
app.post('/api/update-profile', auth, upload.fields([{ name: 'avatar', maxCount: 1 }, { name: 'banner', maxCount: 1 }]), (req, res) => {
    try {
        const { username, bio } = req.body;
        if (username) req.user.username = username;
        if (bio !== undefined) req.user.bio = bio;
        if (req.files?.avatar) req.user.avatar = `/uploads/avatars/${req.files.avatar[0].filename}`;
        if (req.files?.banner) req.user.banner = `/uploads/avatars/${req.files.banner[0].filename}`;
        saveDB();
        res.json({ success: true, user: req.user });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/change-password', auth, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Все поля обязательны' });
        if (newPassword.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
        
        const valid = await bcrypt.compare(oldPassword, req.user.password);
        if (!valid) return res.status(401).json({ error: 'Неверный старый пароль' });
        
        req.user.password = await bcrypt.hash(newPassword, 10);
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/change-email', auth, async (req, res) => {
    try {
        const { newEmail, password } = req.body;
        if (!newEmail || !password) return res.status(400).json({ error: 'Все поля обязательны' });
        
        const valid = await bcrypt.compare(password, req.user.password);
        if (!valid) return res.status(401).json({ error: 'Неверный пароль' });
        
        if (db.users.find(u => u.email === newEmail && u.id !== req.user.id)) {
            return res.status(400).json({ error: 'Email уже используется' });
        }
        
        req.user.email = newEmail;
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/delete-account', auth, (req, res) => {
    try {
        const userId = req.user.id;
        db.users = db.users.filter(u => u.id !== userId);
        db.posts = db.posts.filter(p => p.userId !== userId);
        db.likes = db.likes.filter(l => l.userId !== userId);
        db.comments = db.comments.filter(c => c.userId !== userId);
        db.follows = db.follows.filter(f => f.followerId !== userId && f.followingId !== userId);
        db.blozdaMessages = db.blozdaMessages.filter(m => m.fromId !== userId && m.toId !== userId);
        db.pinnedPosts = db.pinnedPosts.filter(p => p.userId !== userId);
        saveDB();
        res.clearCookie('token');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ----- ПОЛЬЗОВАТЕЛИ -----
app.get('/api/users', auth, (req, res) => {
    try {
        const users = db.users.filter(u => !u.isBanned).map(u => ({
            id: u.id,
            username: u.username,
            avatar: u.avatar,
            banner: u.banner,
            isVerified: u.isVerified || false,
            isAdmin: u.isAdmin || false
        }));
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/users/:id', auth, (req, res) => {
    try {
        const user = db.users.find(u => u.id === req.params.id);
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        if (user.isBanned) return res.status(403).json({ error: 'Пользователь забанен' });

        const followers = db.follows.filter(f => f.followingId === user.id).length;
        const following = db.follows.filter(f => f.followerId === user.id).length;
        const isFollowing = db.follows.some(f => f.followerId === req.user.id && f.followingId === user.id);
        const postCount = db.posts.filter(p => p.userId === user.id).length;
        const isBlocked = db.blockedUsers.some(b => b.userId === req.user.id && b.blockedId === user.id);

        res.json({
            id: user.id,
            username: user.username,
            avatar: user.avatar,
            banner: user.banner || '/default-banner.png',
            bio: user.bio || '',
            isVerified: user.isVerified || false,
            isAdmin: user.isAdmin || false,
            followers,
            following,
            isFollowing,
            isBlocked,
            postCount,
            createdAt: user.createdAt
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ----- ПОДПИСКИ -----
app.post('/api/follow/:id', auth, (req, res) => {
    try {
        const { id } = req.params;
        if (id === req.user.id) return res.status(400).json({ error: 'Нельзя подписаться на себя' });
        const target = db.users.find(u => u.id === id);
        if (!target || target.isBanned) return res.status(404).json({ error: 'Пользователь не найден' });
        
        if (db.blockedUsers.some(b => b.userId === id && b.blockedId === req.user.id)) {
            return res.status(403).json({ error: 'Пользователь заблокировал вас' });
        }

        const existing = db.follows.find(f => f.followerId === req.user.id && f.followingId === id);
        if (existing) {
            db.follows = db.follows.filter(f => f !== existing);
            saveDB();
            return res.json({ success: true, following: false });
        }
        db.follows.push({ followerId: req.user.id, followingId: id, createdAt: new Date().toISOString() });
        saveDB();
        res.json({ success: true, following: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ----- БЛОКИРОВКА -----
app.post('/api/block/:id', auth, (req, res) => {
    try {
        const { id } = req.params;
        if (id === req.user.id) return res.status(400).json({ error: 'Нельзя заблокировать себя' });
        
        const existing = db.blockedUsers.find(b => b.userId === req.user.id && b.blockedId === id);
        if (existing) {
            db.blockedUsers = db.blockedUsers.filter(b => b !== existing);
            saveDB();
            return res.json({ success: true, blocked: false });
        }
        
        db.blockedUsers.push({
            userId: req.user.id,
            blockedId: id,
            createdAt: new Date().toISOString()
        });
        saveDB();
        res.json({ success: true, blocked: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ----- ЖАЛОБЫ -----
app.post('/api/report-user/:id', auth, (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        const user = db.users.find(u => u.id === id);
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        if (user.isAdmin) return res.status(400).json({ error: 'Нельзя жаловаться на админа' });
        
        const existing = db.reportsUser.find(r => r.userId === id && r.reporterId === req.user.id);
        if (existing) return res.status(400).json({ error: 'Вы уже жаловались' });

        db.reportsUser.push({
            id: uuidv4(),
            userId: id,
            reporterId: req.user.id,
            reason: reason || 'Нарушение правил',
            createdAt: new Date().toISOString(),
            resolved: false
        });
        saveDB();
        
        const reports = db.reportsUser.filter(r => r.userId === id && !r.resolved);
        if (reports.length >= 3) {
            user.isBanned = true;
            user.banReason = 'Множественные жалобы от пользователей';
            user.banUntil = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
            saveDB();
            return res.json({ success: true, autoBanned: true });
        }
        
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ===== ПОСТЫ (ГЛАВНОЕ - ИСПРАВЛЕНО!) =====
app.post('/api/posts', auth, upload.single('media'), (req, res) => {
    try {
        const { text, type } = req.body;
        const postType = type || 'text';
        let mediaPath = null, mediaType = null;

        if (req.file) {
            if (req.file.mimetype.startsWith('video/')) {
                mediaPath = `/uploads/videos/${req.file.filename}`;
                mediaType = 'video';
            } else {
                mediaPath = `/uploads/posts/${req.file.filename}`;
                mediaType = 'image';
            }
        }

        const post = {
            id: uuidv4(),
            userId: req.user.id,
            username: req.user.username,
            userAvatar: req.user.avatar,
            text: text || '',
            media: mediaPath,
            mediaType: mediaType,
            type: postType,
            createdAt: new Date().toISOString()
        };
        db.posts.unshift(post);
        saveDB();

        res.json({
            success: true,
            post: {
                ...post,
                likesCount: 0,
                commentsCount: 0,
                isLiked: false,
                isVerified: req.user.isVerified || false,
                isAdmin: req.user.isAdmin || false,
                isPinned: false
            }
        });
    } catch (e) {
        console.error('❌ Ошибка создания поста:', e);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/posts', auth, (req, res) => {
    try {
        console.log('📸 Запрос постов, всего в БД:', db.posts?.length || 0);
        
        if (!db.posts) {
            db.posts = [];
            saveDB();
            return res.json([]);
        }
        
        // Получаем всех пользователей для проверки бана
        const posts = db.posts
            .filter(p => {
                const author = db.users.find(u => u.id === p.userId);
                if (!author) return false;
                // Показываем посты автора, если он не забанен
                // Или если это пост самого пользователя
                if (author.isBanned && author.id !== req.user.id) return false;
                return true;
            })
            .map(p => {
                const likesCount = db.likes ? db.likes.filter(l => l.postId === p.id).length : 0;
                const commentsCount = db.comments ? db.comments.filter(c => c.postId === p.id).length : 0;
                const isLiked = db.likes ? db.likes.some(l => l.postId === p.id && l.userId === req.user.id) : false;
                const author = db.users.find(u => u.id === p.userId);
                const isPinned = db.pinnedPosts ? db.pinnedPosts.some(pp => pp.postId === p.id && pp.userId === p.userId) : false;

                return {
                    ...p,
                    likesCount,
                    commentsCount,
                    isLiked,
                    isPinned,
                    isVerified: author?.isVerified || false,
                    isAdmin: author?.isAdmin || false
                };
            })
            .sort((a, b) => {
                if (a.isPinned && !b.isPinned) return -1;
                if (!a.isPinned && b.isPinned) return 1;
                return new Date(b.createdAt) - new Date(a.createdAt);
            });
        
        console.log('📸 Отправлено постов:', posts.length);
        res.json(posts);
    } catch (e) {
        console.error('❌ Ошибка загрузки постов:', e);
        res.status(500).json({ error: e.message, stack: e.stack });
    }
});

app.get('/api/users/:id/posts', auth, (req, res) => {
    try {
        const user = db.users.find(u => u.id === req.params.id);
        if (!user || user.isBanned) return res.json([]);
        const posts = db.posts
            .filter(p => p.userId === req.params.id)
            .map(p => ({
                ...p,
                likesCount: db.likes.filter(l => l.postId === p.id).length,
                commentsCount: db.comments.filter(c => c.postId === p.id).length
            }));
        res.json(posts);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/posts/:id', auth, (req, res) => {
    try {
        const post = db.posts.find(p => p.id === req.params.id);
        if (!post) return res.status(404).json({ error: 'Пост не найден' });
        if (post.userId !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: 'Нет прав' });

        db.posts = db.posts.filter(p => p.id !== req.params.id);
        db.likes = db.likes.filter(l => l.postId !== req.params.id);
        db.comments = db.comments.filter(c => c.postId !== req.params.id);
        db.pinnedPosts = db.pinnedPosts.filter(p => p.postId !== req.params.id);
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/posts/:id/like', auth, (req, res) => {
    try {
        const existing = db.likes.find(l => l.postId === req.params.id && l.userId === req.user.id);
        if (existing) {
            db.likes = db.likes.filter(l => l !== existing);
        } else {
            db.likes.push({ postId: req.params.id, userId: req.user.id });
        }
        saveDB();
        const count = db.likes.filter(l => l.postId === req.params.id).length;
        res.json({ likes: count, liked: !existing });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/posts/:id/comment', auth, upload.single('commentFile'), (req, res) => {
    try {
        const { text } = req.body;
        const postId = req.params.id;
        
        const post = db.posts.find(p => p.id === postId);
        if (!post) return res.status(404).json({ error: 'Пост не найден' });

        if (!text && !req.file) return res.status(400).json({ error: 'Введите текст или прикрепите файл' });

        let filePath = null, fileType = null;
        if (req.file) {
            filePath = `/uploads/comments/${req.file.filename}`;
            if (req.file.mimetype.startsWith('audio/')) fileType = 'audio';
            else if (req.file.mimetype.startsWith('image/')) fileType = 'image';
            else if (req.file.mimetype.startsWith('video/')) fileType = 'video';
        }

        const comment = {
            id: uuidv4(),
            postId: postId,
            userId: req.user.id,
            username: req.user.username,
            userAvatar: req.user.avatar,
            text: text || '',
            file: filePath,
            fileType: fileType,
            createdAt: new Date().toISOString()
        };
        
        db.comments.push(comment);
        saveDB();
        res.json(comment);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/posts/:id/comments', auth, (req, res) => {
    try {
        const comments = db.comments.filter(c => c.postId === req.params.id);
        res.json(comments);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/posts/:id/repost', auth, (req, res) => {
    try {
        const original = db.posts.find(p => p.id === req.params.id);
        if (!original) return res.status(404).json({ error: 'Не найден' });
        const author = db.users.find(u => u.id === original.userId);
        if (author?.isBanned) return res.status(403).json({ error: 'Пост забаненного пользователя' });

        const repost = {
            id: uuidv4(),
            userId: req.user.id,
            username: req.user.username,
            userAvatar: req.user.avatar,
            text: `🔄 Репост @${original.username}: ${original.text}`,
            media: original.media,
            mediaType: original.mediaType,
            type: original.type,
            originalPostId: original.id,
            isRepost: true,
            createdAt: new Date().toISOString()
        };
        db.posts.unshift(repost);
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/pin/:id', auth, (req, res) => {
    try {
        const post = db.posts.find(p => p.id === req.params.id);
        if (!post) return res.status(404).json({ error: 'Пост не найден' });
        if (post.userId !== req.user.id) return res.status(403).json({ error: 'Не ваш пост' });
        
        const existing = db.pinnedPosts.find(p => p.postId === post.id && p.userId === req.user.id);
        if (existing) {
            db.pinnedPosts = db.pinnedPosts.filter(p => p !== existing);
            saveDB();
            return res.json({ success: true, pinned: false });
        }
        
        db.pinnedPosts.push({
            postId: post.id,
            userId: req.user.id,
            createdAt: new Date().toISOString()
        });
        saveDB();
        res.json({ success: true, pinned: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/forward-post', auth, (req, res) => {
    try {
        const { postId, toId } = req.body;
        if (!postId || !toId) return res.status(400).json({ error: 'Не указаны данные' });
        
        const post = db.posts.find(p => p.id === postId);
        if (!post) return res.status(404).json({ error: 'Пост не найден' });
        
        const toUser = db.users.find(u => u.id === toId);
        if (!toUser) return res.status(404).json({ error: 'Пользователь не найден' });
        
        if (!db.blozdaMessages) db.blozdaMessages = [];
        const message = {
            id: uuidv4(),
            fromId: req.user.id,
            toId: toId,
            text: `📤 Пересланный пост от @${post.username}: ${post.text || ''}`,
            file: post.media,
            fileType: post.mediaType || 'image',
            forwardedPost: {
                id: post.id,
                text: post.text,
                media: post.media,
                mediaType: post.mediaType,
                username: post.username
            },
            createdAt: new Date().toISOString(),
            read: false
        };
        db.blozdaMessages.push(message);
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/report/:id', auth, (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        const post = db.posts.find(p => p.id === id);
        if (!post) return res.status(404).json({ error: 'Пост не найден' });
        const existing = db.reports.find(r => r.postId === id && r.reporterId === req.user.id);
        if (existing) return res.status(400).json({ error: 'Вы уже жаловались' });

        db.reports.push({
            id: uuidv4(),
            postId: id,
            reporterId: req.user.id,
            reason: reason || 'Нарушение правил',
            createdAt: new Date().toISOString(),
            resolved: false
        });
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ----- BLOZDA -----
app.get('/api/blozda/following', auth, (req, res) => {
    try {
        const following = db.follows.filter(f => f.followerId === req.user.id);
        const users = db.users.filter(u => 
            following.some(f => f.followingId === u.id) && 
            !u.isBanned &&
            !db.blockedUsers.some(b => b.userId === req.user.id && b.blockedId === u.id)
        );
        res.json(users.map(u => ({
            id: u.id,
            username: u.username,
            avatar: u.avatar,
            isVerified: u.isVerified || false
        })));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/blozda/messages/:userId', auth, (req, res) => {
    try {
        const { userId } = req.params;
        
        if (db.blockedUsers.some(b => b.userId === req.user.id && b.blockedId === userId)) {
            return res.status(403).json({ error: 'Пользователь заблокирован' });
        }
        if (db.blockedUsers.some(b => b.userId === userId && b.blockedId === req.user.id)) {
            return res.status(403).json({ error: 'Вы заблокированы' });
        }
        
        const messages = db.blozdaMessages?.filter(m => 
            (m.fromId === req.user.id && m.toId === userId) ||
            (m.fromId === userId && m.toId === req.user.id)
        ) || [];
        res.json(messages);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/blozda/messages', auth, upload.fields([{ name: 'chatFile', maxCount: 1 }, { name: 'voiceMessage', maxCount: 1 }]), (req, res) => {
    try {
        const { toId, text } = req.body;
        if (!toId) return res.status(400).json({ error: 'Не указан получатель' });
        
        if (db.blockedUsers.some(b => b.userId === req.user.id && b.blockedId === toId)) {
            return res.status(403).json({ error: 'Пользователь заблокирован' });
        }
        if (db.blockedUsers.some(b => b.userId === toId && b.blockedId === req.user.id)) {
            return res.status(403).json({ error: 'Вы заблокированы' });
        }
        
        const recentMessages = db.blozdaMessages.filter(m => 
            m.fromId === req.user.id && 
            new Date(m.createdAt) > new Date(Date.now() - 10000)
        );
        if (recentMessages.length >= 5) {
            req.user.isBanned = true;
            req.user.banReason = 'Спам в мессенджере';
            req.user.banUntil = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
            saveDB();
            return res.status(403).json({ error: 'Вы забанены за спам на 3 дня' });
        }
        
        let file = null;
        let fileType = null;
        
        if (req.files?.chatFile) {
            const f = req.files.chatFile[0];
            file = `/uploads/chat/${f.filename}`;
            if (f.mimetype.startsWith('image/')) fileType = 'image';
            else if (f.mimetype.startsWith('video/')) fileType = 'video';
            else if (f.mimetype.startsWith('audio/')) fileType = 'audio';
            else fileType = 'file';
        }
        
        if (req.files?.voiceMessage) {
            const f = req.files.voiceMessage[0];
            file = `/uploads/voice/${f.filename}`;
            fileType = 'voice';
        }
        
        if (!db.blozdaMessages) db.blozdaMessages = [];
        const message = {
            id: uuidv4(),
            fromId: req.user.id,
            toId,
            text: text || '',
            file: file,
            fileType: fileType,
            createdAt: new Date().toISOString(),
            read: false
        };
        db.blozdaMessages.push(message);
        saveDB();
        res.json(message);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/blozda/messages/:id', auth, (req, res) => {
    try {
        if (!db.blozdaMessages) db.blozdaMessages = [];
        const msg = db.blozdaMessages.find(m => m.id === req.params.id);
        if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });
        if (msg.fromId !== req.user.id) {
            return res.status(403).json({ error: 'Нельзя удалить чужое сообщение' });
        }
        db.blozdaMessages = db.blozdaMessages.filter(m => m.id !== req.params.id);
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/blozda/clear-chat/:userId', auth, (req, res) => {
    try {
        const { userId } = req.params;
        db.blozdaMessages = db.blozdaMessages.filter(m => 
            !(m.fromId === req.user.id && m.toId === userId) &&
            !(m.fromId === userId && m.toId === req.user.id)
        );
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ----- АДМИН -----
app.get('/api/admin/stats', auth, adminAuth, (req, res) => {
    try {
        const stats = {
            users: db.users.length,
            posts: db.posts.length,
            comments: db.comments.length,
            likes: db.likes.length,
            reports: db.reports.filter(r => !r.resolved).length,
            reportsUser: db.reportsUser.filter(r => !r.resolved).length,
            follows: db.follows.length,
            banned: db.users.filter(u => u.isBanned).length
        };
        res.json(stats);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/users', auth, adminAuth, (req, res) => {
    try {
        const users = db.users.map(u => ({
            id: u.id,
            username: u.username,
            email: u.email,
            avatar: u.avatar,
            isAdmin: u.isAdmin || false,
            isVerified: u.isVerified || false,
            isBanned: u.isBanned || false,
            banReason: u.banReason || '',
            banUntil: u.banUntil || null,
            postCount: db.posts.filter(p => p.userId === u.id).length
        }));
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/admin/verify/:id', auth, adminAuth, (req, res) => {
    try {
        const user = db.users.find(u => u.id === req.params.id);
        if (!user) return res.status(404).json({ error: 'Не найден' });
        user.isVerified = !user.isVerified;
        saveDB();
        res.json({ success: true, isVerified: user.isVerified });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/admin/ban/:id', auth, adminAuth, (req, res) => {
    try {
        const { id } = req.params;
        const { reason, duration } = req.body;
        const user = db.users.find(u => u.id === id);
        if (!user) return res.status(404).json({ error: 'Не найден' });
        if (user.isAdmin) return res.status(400).json({ error: 'Нельзя забанить админа' });
        if (user.id === req.user.id) return res.status(400).json({ error: 'Нельзя забанить себя' });
        
        if (user.isBanned) {
            user.isBanned = false;
            user.banReason = '';
            user.banUntil = null;
        } else {
            user.isBanned = true;
            user.banReason = reason || 'Нарушение правил';
            const days = parseInt(duration) || 3;
            user.banUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
        }
        saveDB();
        res.json({ success: true, isBanned: user.isBanned });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/admin/users/:id', auth, adminAuth, (req, res) => {
    try {
        if (req.params.id === req.user.id) return res.status(400).json({ error: 'Нельзя удалить себя' });
        const user = db.users.find(u => u.id === req.params.id);
        if (!user) return res.status(404).json({ error: 'Не найден' });
        if (user.isAdmin) return res.status(400).json({ error: 'Нельзя удалить админа' });

        db.users = db.users.filter(u => u.id !== req.params.id);
        db.posts = db.posts.filter(p => p.userId !== req.params.id);
        db.likes = db.likes.filter(l => l.userId !== req.params.id);
        db.comments = db.comments.filter(c => c.userId !== req.params.id);
        db.follows = db.follows.filter(f => f.followerId !== req.params.id && f.followingId !== req.params.id);
        db.blozdaMessages = db.blozdaMessages.filter(m => m.fromId !== req.params.id && m.toId !== req.params.id);
        db.pinnedPosts = db.pinnedPosts.filter(p => p.userId !== req.params.id);
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/posts', auth, adminAuth, (req, res) => {
    try {
        const posts = db.posts.map(p => ({
            ...p,
            likesCount: db.likes.filter(l => l.postId === p.id).length,
            commentsCount: db.comments.filter(c => c.postId === p.id).length
        }));
        res.json(posts);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/reports', auth, adminAuth, (req, res) => {
    try {
        const reports = db.reports.filter(r => !r.resolved);
        const posts = db.posts.filter(p => reports.some(r => r.postId === p.id));
        const users = db.users.filter(u => reports.some(r => r.reporterId === u.id));
        
        res.json(reports.map(r => ({
            ...r,
            post: posts.find(p => p.id === r.postId),
            reporter: users.find(u => u.id === r.reporterId)
        })));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/reports-user', auth, adminAuth, (req, res) => {
    try {
        const reports = db.reportsUser.filter(r => !r.resolved);
        const users = db.users.filter(u => reports.some(r => r.userId === u.id));
        const reporters = db.users.filter(u => reports.some(r => r.reporterId === u.id));
        
        res.json(reports.map(r => ({
            ...r,
            user: users.find(u => u.id === r.userId),
            reporter: reporters.find(u => u.id === r.reporterId)
        })));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/admin/reports/:id/resolve', auth, adminAuth, (req, res) => {
    try {
        const { id } = req.params;
        const { action } = req.body;
        
        const report = db.reports.find(r => r.id === id);
        if (!report) return res.status(404).json({ error: 'Жалоба не найдена' });
        
        report.resolved = true;
        
        if (action === 'delete') {
            db.posts = db.posts.filter(p => p.id !== report.postId);
            db.likes = db.likes.filter(l => l.postId !== report.postId);
            db.comments = db.comments.filter(c => c.postId !== report.postId);
        }
        
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/admin/reports-user/:id/resolve', auth, adminAuth, (req, res) => {
    try {
        const { id } = req.params;
        const { action } = req.body;
        
        const report = db.reportsUser.find(r => r.id === id);
        if (!report) return res.status(404).json({ error: 'Жалоба не найдена' });
        
        report.resolved = true;
        
        if (action === 'ban') {
            const user = db.users.find(u => u.id === report.userId);
            if (user && !user.isAdmin) {
                user.isBanned = true;
                user.banReason = 'Жалобы от пользователей';
                user.banUntil = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
            }
        }
        
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ===== СТРАНИЦЫ =====
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/blozda', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'blozda.html'));
});

// ===== ОБРАБОТКА ОШИБОК =====
app.use((err, req, res, next) => {
    console.error('❌ Ошибка:', err.stack);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// ===== ЗАПУСК =====
const server = require('http').createServer(app);
server.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔════════════════════════════════════════════════════════╗
║   🔥 OFQ + Blozda запущены!                           ║
║   📱 http://localhost:${PORT}                           ║
║   💬 http://localhost:${PORT}/blozda                    ║
║   👑 1kz / admin@ofq.com / admin123                   ║
║   📸 Постов в БД: ${db.posts?.length || 0}              ║
╚════════════════════════════════════════════════════════╝
    `);
});