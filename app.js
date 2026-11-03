const express = require('express');
const cors = require('cors');
const argon2 = require('@node-rs/argon2');
const jwt = require('jsonwebtoken');
const con = require('./db_config');

const JWT_KEY = 'thisisthesecretforjwt';
const revokedTokens = new Set();
const app = express();
app.use(cors());
app.use(express.json());

function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            message: 'Unauthorized'
        });
    }
    const token = authHeader.split(' ')[1];
    if (revokedTokens.has(token)) {
        return res.status(401).json({
            message: 'Time out. Please login again.'
        });
    }
    jwt.verify(token, JWT_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({
                message: 'Invalid or expired token'
            });
        }
        req.user = decoded;
        next();
    });
}

function verifyAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({
            message: 'Admin access required'
        });
    }
    next();
}

function verifyStaff(req, res, next) {
    if (!req.user || req.user.role !== 'staff') {
        return res.status(403).json({
            message: 'Staff access required'
        });
    }
    next();
}

// hash password
app.get('/api/password/:raw', (req, res) => {
    const hash = argon2.hashSync(req.params.raw);
    console.log(hash.length);
    res.send(hash);
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM users WHERE username=?";
    con.query(sql, [username], (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).send('DB error');
        }

        if (result.length != 1) {
            return res.status(401).send('Wrong username');
        }

        const hash = result[0].password;
        const same = argon2.verify(hash, password);
        if (!same) {
            return res.status(401).send('Wrong password');
        }

        const payload = { user_id: result[0].user_id, username: result[0].username, role: result[0].role };
        const token = jwt.sign(payload, JWT_KEY, { expiresIn: '1d' });
        return res.json({ token });
    });
});

app.post('/api/logout', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            message: 'Token not found'
        });
    }
    const token = authHeader.split(' ')[1];
    revokedTokens.add(token);
    return res.json({
        message: 'Logout successful'
    });
});

//ดึงข้อมูลprofileของuser
app.get('/api/profile', verifyToken, (req, res) => {
    res.json({
        message: 'Access granted',
        user: req.user
    });
});

//delete event
app.delete('/api/events/:id', verifyToken, verifyStaff, (req, res) => {
    const { id } = req.params;
    const staff_id = req.user.user_id;
    const sql = `
        DELETE FROM event
        WHERE event_id = ?
        AND created_by = ?
    `;
    con.query(sql, [id, staff_id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                message: 'Database error'
            });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: 'Event not found or you do not have permission to delete this event'
            });
        }
        return res.status(200).json({
            message: 'Event deleted successfully'
        });
    });
});

app.get('/api/dashboard/events', verifyToken, (req, res) => {
    const { school_id, major_id } = req.query;
    let sql = `SELECT * FROM event WHERE event_status = 'enable'`;
    const params = [];
    if (school_id) {
        sql += ` AND school_id = ?`;
        params.push(school_id);
    }
    if (major_id) {
        sql += ` AND major_id = ?`;
        params.push(major_id);
    }
    sql += ` ORDER BY created_at DESC`;
    con.query(sql, params, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                message: 'Database error'
            });
        }
        return res.status(200).json({
            total_events: result.length,
            events: result
        });
    });
});

//--------ADMIN SERVICE-------//

//add user
app.post('/api/admin/add', verifyToken, verifyAdmin, async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || typeof password !== 'string' || !password ||
        !['user', 'staff', 'admin'].includes(role)) {
        return res.status(400).json({
            message: 'Invalid username, password or role'
        });
    }
    try {
        const hash = await argon2.hash(password);
        const sql = `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`;
        con.query(sql, [username, hash, role], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({
                        message: 'Username already exists'
                    });
                }
                console.error(err);
                return res.status(500).json({ message: 'Database error' });
            }
            return res.status(201).json({
                message: 'User created',
                user_id: result.insertId
            });
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Password hashing error' });
    }
});

//delete user
app.delete('/api/admin/delete/:id', verifyToken, verifyAdmin, (req, res) => {
    const sql = 'DELETE FROM users WHERE user_id = ?';
    con.query(sql, [req.params.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        return res.json({ message: 'User deleted' });
    });
});

//toggle event
app.patch('/api/admin/events/:id/toggle', verifyToken, verifyAdmin, (req, res) => {
    const { id } = req.params;
    const sql = `
        UPDATE event
        SET status = CASE
            WHEN status = 1 THEN 0
            ELSE 1
        END
        WHERE event_id = ?
    `;
    con.query(sql, [id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                message: 'Database error'
            });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: 'Event not found'
            });
        }
        return res.json({
            message: 'Event status updated successfully'
        });
    });
});

//toggle user status
app.patch('/api/admin/users/:id/toggle', verifyToken, verifyAdmin, (req, res) => {
    const { id } = req.params;
    const sql = `
        UPDATE users
        SET user_status = CASE
            WHEN user_status = 1 THEN 0
            ELSE 1
        END
        WHERE user_id = ?
    `;
    con.query(sql, [id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                message: 'Database error'
            });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: 'User not found'
            });
        }
        return res.json({
            message: 'User status updated successfully'
        });
    });
});

//--------STAFF SERVICE-------//

//Create Event
app.post('/api/staff/events', verifyToken, verifyStaff, (req, res) => {
    const {
        major_id,
        event_title,
        event_details,
        img_path,
        form_url
    } = req.body;
    const staff_id = req.user.user_id;
    if (!major_id || !event_title || !event_details) {
        return res.status(400).json({
            message: 'Please provide major_id, event_title and event_details'
        });
    }
    const sql = `
        INSERT INTO event (
            major_id,
            event_title,
            event_details,
            img_path,
            form_url,
            event_status,
            create_at,
            created_by
        )
        VALUES (?, ?, ?, ?, ?, 'pending', NOW(), ?)
    `;
    const values = [
        major_id,
        event_title,
        event_details,
        img_path || null,
        form_url || null,
        staff_id
    ];
    con.query(sql, values, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                message: 'Database error'
            });
        }
        return res.status(201).json({
            message: 'Event created successfully. Waiting for admin approval.',
            event_id: result.insertId,
            created_by: staff_id
        });
    });
});

//staff dashboard
app.get('/api/staff/myevents', verifyToken, verifyStaff, (req, res) => {
    const staff_id = req.user.user_id;
    const sql = `
        SELECT *
        FROM event
        WHERE created_by = ?
        ORDER BY create_at DESC
    `;
    con.query(sql, [staff_id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                message: 'Database error'
            });
        }
        return res.status(200).json({
            total_events: result.length,
            events: result
        });
    });
});

//edit event
app.put('/api/staff/events/:id', verifyToken, verifyStaff, (req, res) => {
    const { id } = req.params;
    const staff_id = req.user.user_id;
    const {
        major_id,
        event_title,
        event_details,
        img_path,
        form_url
    } = req.body;
    if (!major_id || !event_title || !event_details) {
        return res.status(400).json({
            message: 'Please provide major_id, event_title and event_details'
        });
    }
    const sql = `
        UPDATE event
        SET
            major_id = ?,
            event_title = ?,
            event_details = ?,
            img_path = ?,
            form_url = ?,
            event_status = 'pending'
        WHERE event_id = ?
        AND created_by = ?
    `;
    const values = [
        major_id,
        event_title,
        event_details,
        img_path || null,
        form_url || null,
        id,
        staff_id
    ];
    con.query(sql, values, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                message: 'Database error'
            });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: 'Event not found or you do not have permission to edit this event'
            });
        }
        return res.status(200).json({
            message: 'Event updated successfully. Waiting for admin approval.'
        });
    });
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});