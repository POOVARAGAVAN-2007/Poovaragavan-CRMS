const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const db = require('./database');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret';
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '24h';

// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Multer config for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'video/mp4'];
    cb(null, allowed.includes(file.mimetype));
  }
});

// ==================== JWT MIDDLEWARE ====================
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
}

function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Forbidden. Insufficient permissions.' });
    }
    next();
  };
}

// ==================== HELPER FUNCTIONS ====================
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function logAudit(userId, action, entityType, entityId, details, ip) {
  dbRun(`INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
    [userId, action, entityType, entityId, details, ip]);
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, phone, address, full_name } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'Username, email, and password are required.' });
    }

    const existing = await dbGet(`SELECT user_id FROM users WHERE username = ? OR email = ?`, [username, email]);
    if (existing) {
      return res.status(409).json({ success: false, message: 'Username or email already exists.' });
    }

    const hash = bcrypt.hashSync(password, 10);
    const result = await dbRun(
      `INSERT INTO users (username, email, password_hash, role, phone, address, full_name) VALUES (?, ?, ?, 'CITIZEN', ?, ?, ?)`,
      [username, email, hash, phone || null, address || null, full_name || username]
    );

    logAudit(result.lastID, 'REGISTER', 'USER', result.lastID, 'New citizen registered', req.ip);
    res.status(201).json({ success: true, message: 'Registration successful. Please login.', userId: result.lastID });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Registration failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    const user = await dbGet(`SELECT * FROM users WHERE username = ? OR email = ?`, [username, username]);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }
    if (!user.is_active) {
      return res.status(403).json({ success: false, message: 'Account is deactivated.' });
    }
    if (role && user.role !== role.toUpperCase()) {
      return res.status(403).json({ success: false, message: 'Invalid role selected.' });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { userId: user.user_id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    logAudit(user.user_id, 'LOGIN', 'USER', user.user_id, 'User logged in', req.ip);
    res.json({
      success: true,
      message: 'Login successful.',
      token,
      user: {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        fullName: user.full_name,
        phone: user.phone
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Login failed.' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = await dbGet(`SELECT user_id, username, email, role, phone, address, full_name, is_active, created_at FROM users WHERE user_id = ?`, [req.user.userId]);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch profile.' });
  }
});

app.put('/api/auth/profile', authenticate, async (req, res) => {
  try {
    const { full_name, phone, address } = req.body;
    await dbRun(
      `UPDATE users SET full_name = ?, phone = ?, address = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?`,
      [full_name, phone, address, req.user.userId]
    );
    logAudit(req.user.userId, 'UPDATE_PROFILE', 'USER', req.user.userId, 'Profile updated', req.ip);
    res.json({ success: true, message: 'Profile updated successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update profile.' });
  }
});

app.post('/api/auth/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await dbGet(`SELECT password_hash FROM users WHERE user_id = ?`, [req.user.userId]);
    if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect.' });
    }
    const hash = bcrypt.hashSync(newPassword, 10);
    await dbRun(`UPDATE users SET password_hash = ? WHERE user_id = ?`, [hash, req.user.userId]);
    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to change password.' });
  }
});

// ==================== REPORT ROUTES ====================
app.post('/api/reports', authenticate, authorize('CITIZEN', 'ADMIN'), upload.array('evidence', 5), async (req, res) => {
  try {
    const { title, description, crime_type, location, latitude, longitude, incident_date } = req.body;
    if (!title || !description || !crime_type || !location) {
      return res.status(400).json({ success: false, message: 'Title, description, crime type, and location are required.' });
    }

    const result = await dbRun(
      `INSERT INTO crime_reports (user_id, title, description, crime_type, location, latitude, longitude, incident_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.userId, title, description, crime_type, location, latitude || null, longitude || null, incident_date || null]
    );

    const reportId = result.lastID;

    // Save evidence files
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        await dbRun(
          `INSERT INTO evidence (report_id, file_name, file_path, file_type, description, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)`,
          [reportId, file.originalname, `/uploads/${file.filename}`, file.mimetype.split('/')[0], null, req.user.userId]
        );
      }
    }

    // Create notification for user
    await dbRun(
      `INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)`,
      [req.user.userId, `Report #${reportId} filed successfully. Status: PENDING`, 'STATUS_UPDATE']
    );

    logAudit(req.user.userId, 'CREATE', 'REPORT', reportId, `New report created: ${title}`, req.ip);
    res.status(201).json({ success: true, message: 'Report filed successfully.', reportId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to file report.' });
  }
});

app.get('/api/reports/my', authenticate, authorize('CITIZEN'), async (req, res) => {
  try {
    const reports = await dbAll(
      `SELECT r.*, u.full_name as officer_name FROM crime_reports r 
       LEFT JOIN users u ON r.assigned_officer_id = u.user_id 
       WHERE r.user_id = ? ORDER BY r.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, reports });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch reports.' });
  }
});

app.get('/api/reports', authenticate, authorize('ADMIN', 'OFFICER'), async (req, res) => {
  try {
    const { status, search } = req.query;
    let sql = `SELECT r.*, u.full_name as citizen_name, o.full_name as officer_name FROM crime_reports r 
               LEFT JOIN users u ON r.user_id = u.user_id 
               LEFT JOIN users o ON r.assigned_officer_id = o.user_id WHERE 1=1`;
    const params = [];
    if (status) { sql += ` AND r.status = ?`; params.push(status); }
    if (search) { sql += ` AND (r.title LIKE ? OR r.location LIKE ? OR r.crime_type LIKE ?)`; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
    sql += ` ORDER BY r.created_at DESC`;
    const reports = await dbAll(sql, params);
    res.json({ success: true, reports });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch reports.' });
  }
});

app.get('/api/reports/:id', authenticate, async (req, res) => {
  try {
    const report = await dbGet(
      `SELECT r.*, u.full_name as citizen_name, u.phone as citizen_phone, o.full_name as officer_name 
       FROM crime_reports r 
       LEFT JOIN users u ON r.user_id = u.user_id 
       LEFT JOIN users o ON r.assigned_officer_id = o.user_id 
       WHERE r.report_id = ?`,
      [req.params.id]
    );
    if (!report) return res.status(404).json({ success: false, message: 'Report not found.' });

    // Check ownership for citizens
    if (req.user.role === 'CITIZEN' && report.user_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    const updates = await dbAll(
      `SELECT cu.*, u.full_name as officer_name FROM case_updates cu 
       LEFT JOIN users u ON cu.officer_id = u.user_id 
       WHERE cu.report_id = ? ORDER BY cu.created_at DESC`,
      [req.params.id]
    );
    const suspects = await dbAll(`SELECT * FROM suspects WHERE report_id = ?`, [req.params.id]);
    const evidence = await dbAll(
      `SELECT e.*, u.full_name as uploaded_by_name FROM evidence e 
       LEFT JOIN users u ON e.uploaded_by = u.user_id 
       WHERE e.report_id = ?`,
      [req.params.id]
    );

    res.json({ success: true, report, updates, suspects, evidence });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch report.' });
  }
});

app.put('/api/reports/:id', authenticate, async (req, res) => {
  try {
    const report = await dbGet(`SELECT * FROM crime_reports WHERE report_id = ?`, [req.params.id]);
    if (!report) return res.status(404).json({ success: false, message: 'Report not found.' });
    if (req.user.role === 'CITIZEN' && report.user_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    const { title, description, crime_type, location, incident_date } = req.body;
    await dbRun(
      `UPDATE crime_reports SET title = ?, description = ?, crime_type = ?, location = ?, incident_date = ?, updated_at = CURRENT_TIMESTAMP WHERE report_id = ?`,
      [title, description, crime_type, location, incident_date, req.params.id]
    );
    logAudit(req.user.userId, 'UPDATE', 'REPORT', req.params.id, 'Report updated', req.ip);
    res.json({ success: true, message: 'Report updated successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update report.' });
  }
});

app.delete('/api/reports/:id', authenticate, async (req, res) => {
  try {
    const report = await dbGet(`SELECT * FROM crime_reports WHERE report_id = ?`, [req.params.id]);
    if (!report) return res.status(404).json({ success: false, message: 'Report not found.' });
    if (req.user.role === 'CITIZEN' && report.user_id !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }

    await dbRun(`DELETE FROM crime_reports WHERE report_id = ?`, [req.params.id]);
    logAudit(req.user.userId, 'DELETE', 'REPORT', req.params.id, 'Report deleted', req.ip);
    res.json({ success: true, message: 'Report deleted successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete report.' });
  }
});

// ==================== CASE UPDATE ROUTES ====================
app.post('/api/case-updates', authenticate, authorize('OFFICER', 'ADMIN'), async (req, res) => {
  try {
    const { report_id, status, notes } = req.body;
    if (!report_id || !status || !notes) {
      return res.status(400).json({ success: false, message: 'Report ID, status, and notes are required.' });
    }

    const result = await dbRun(
      `INSERT INTO case_updates (report_id, officer_id, status, notes) VALUES (?, ?, ?, ?)`,
      [report_id, req.user.userId, status, notes]
    );

    // Update report status
    await dbRun(`UPDATE crime_reports SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE report_id = ?`, [status, report_id]);

    // Notify citizen
    const report = await dbGet(`SELECT user_id FROM crime_reports WHERE report_id = ?`, [report_id]);
    if (report) {
      await dbRun(
        `INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)`,
        [report.user_id, `Case #${report_id} status updated to "${status}"`, 'STATUS_UPDATE']
      );
    }

    logAudit(req.user.userId, 'UPDATE_STATUS', 'REPORT', report_id, `Status changed to ${status}`, req.ip);
    res.status(201).json({ success: true, message: 'Case updated successfully.', updateId: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update case.' });
  }
});

app.get('/api/case-updates/:reportId', authenticate, async (req, res) => {
  try {
    const updates = await dbAll(
      `SELECT cu.*, u.full_name as officer_name FROM case_updates cu 
       LEFT JOIN users u ON cu.officer_id = u.user_id 
       WHERE cu.report_id = ? ORDER BY cu.created_at DESC`,
      [req.params.reportId]
    );
    res.json({ success: true, updates });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch updates.' });
  }
});

// ==================== OFFICER ROUTES ====================
app.get('/api/officer/cases', authenticate, authorize('OFFICER'), async (req, res) => {
  try {
    const reports = await dbAll(
      `SELECT r.*, u.full_name as citizen_name FROM crime_reports r 
       LEFT JOIN users u ON r.user_id = u.user_id 
       WHERE r.assigned_officer_id = ? OR r.assigned_officer_id IS NULL ORDER BY r.priority DESC, r.created_at DESC`,
      [req.user.userId]
    );
    res.json({ success: true, reports });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch cases.' });
  }
});

app.patch('/api/officer/assign/:reportId', authenticate, authorize('OFFICER'), async (req, res) => {
  try {
    await dbRun(`UPDATE crime_reports SET assigned_officer_id = ?, updated_at = CURRENT_TIMESTAMP WHERE report_id = ?`, [req.user.userId, req.params.reportId]);
    const report = await dbGet(`SELECT user_id FROM crime_reports WHERE report_id = ?`, [req.params.reportId]);
    if (report) {
      await dbRun(
        `INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)`,
        [report.user_id, `Officer assigned to your case #${req.params.reportId}`, 'ASSIGNMENT']
      );
    }
    res.json({ success: true, message: 'Case assigned successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to assign case.' });
  }
});

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/users', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const users = await dbAll(`SELECT user_id, username, email, role, phone, full_name, is_active, created_at FROM users ORDER BY created_at DESC`);
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch users.' });
  }
});

app.patch('/api/admin/users/:id/status', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const { is_active } = req.body;
    await dbRun(`UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?`, [is_active ? 1 : 0, req.params.id]);
    logAudit(req.user.userId, 'UPDATE_USER_STATUS', 'USER', req.params.id, `Status changed to ${is_active}`, req.ip);
    res.json({ success: true, message: 'User status updated.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update user.' });
  }
});

app.delete('/api/admin/users/:id', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    await dbRun(`DELETE FROM users WHERE user_id = ?`, [req.params.id]);
    logAudit(req.user.userId, 'DELETE_USER', 'USER', req.params.id, 'User deleted', req.ip);
    res.json({ success: true, message: 'User deleted.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete user.' });
  }
});

app.get('/api/admin/stats', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const totalUsers = await dbGet(`SELECT COUNT(*) as count FROM users`);
    const totalReports = await dbGet(`SELECT COUNT(*) as count FROM crime_reports`);
    const pending = await dbGet(`SELECT COUNT(*) as count FROM crime_reports WHERE status = 'PENDING'`);
    const investigating = await dbGet(`SELECT COUNT(*) as count FROM crime_reports WHERE status = 'INVESTIGATING'`);
    const resolved = await dbGet(`SELECT COUNT(*) as count FROM crime_reports WHERE status = 'RESOLVED'`);
    const closed = await dbGet(`SELECT COUNT(*) as count FROM crime_reports WHERE status = 'CLOSED'`);
    const citizens = await dbGet(`SELECT COUNT(*) as count FROM users WHERE role = 'CITIZEN'`);
    const officers = await dbGet(`SELECT COUNT(*) as count FROM users WHERE role = 'OFFICER'`);
    const crimeTypes = await dbAll(`SELECT crime_type, COUNT(*) as count FROM crime_reports GROUP BY crime_type`);
    const monthly = await dbAll(`SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count FROM crime_reports GROUP BY month ORDER BY month DESC LIMIT 6`);

    res.json({
      success: true,
      stats: {
        totalUsers: totalUsers.count,
        totalReports: totalReports.count,
        pending: pending.count,
        investigating: investigating.count,
        resolved: resolved.count,
        closed: closed.count,
        totalCitizens: citizens.count,
        totalOfficers: officers.count,
        crimeTypeDistribution: crimeTypes,
        monthlyTrend: monthly
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch stats.' });
  }
});

app.get('/api/admin/audit-logs', authenticate, authorize('ADMIN'), async (req, res) => {
  try {
    const logs = await dbAll(
      `SELECT al.*, u.username FROM audit_logs al LEFT JOIN users u ON al.user_id = u.user_id ORDER BY al.timestamp DESC LIMIT 100`
    );
    res.json({ success: true, logs });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch audit logs.' });
  }
});

// ==================== NOTIFICATIONS ====================
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const notifs = await dbAll(
      `SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`,
      [req.user.userId]
    );
    const unread = await dbGet(`SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0`, [req.user.userId]);
    res.json({ success: true, notifications: notifs, unreadCount: unread.count });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch notifications.' });
  }
});

app.patch('/api/notifications/:id/read', authenticate, async (req, res) => {
  try {
    await dbRun(`UPDATE notifications SET is_read = 1 WHERE notification_id = ? AND user_id = ?`, [req.params.id, req.user.userId]);
    res.json({ success: true, message: 'Marked as read.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update notification.' });
  }
});

app.patch('/api/notifications/read-all', authenticate, async (req, res) => {
  try {
    await dbRun(`UPDATE notifications SET is_read = 1 WHERE user_id = ?`, [req.user.userId]);
    res.json({ success: true, message: 'All notifications marked as read.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update notifications.' });
  }
});

// ==================== EVIDENCE UPLOAD ====================
app.post('/api/evidence/:reportId', authenticate, upload.array('files', 5), async (req, res) => {
  try {
    const reportId = req.params.reportId;
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ success: false, message: 'No files uploaded.' });
    }
    for (const file of req.files) {
      await dbRun(
        `INSERT INTO evidence (report_id, file_name, file_path, file_type, description, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)`,
        [reportId, file.originalname, `/uploads/${file.filename}`, file.mimetype.split('/')[0], req.body.description || null, req.user.userId]
      );
    }
    res.json({ success: true, message: 'Evidence uploaded successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to upload evidence.' });
  }
});

// ==================== PUBLIC STATS ====================
app.get('/api/public/stats', async (req, res) => {
  try {
    const totalReports = await dbGet(`SELECT COUNT(*) as count FROM crime_reports`);
    const resolved = await dbGet(`SELECT COUNT(*) as count FROM crime_reports WHERE status = 'RESOLVED'`);
    const pending = await dbGet(`SELECT COUNT(*) as count FROM crime_reports WHERE status = 'PENDING'`);
    const officers = await dbGet(`SELECT COUNT(*) as count FROM users WHERE role = 'OFFICER'`);
    const citizens = await dbGet(`SELECT COUNT(*) as count FROM users WHERE role = 'CITIZEN'`);
    const crimeTypes = await dbAll(`SELECT crime_type, COUNT(*) as count FROM crime_reports GROUP BY crime_type`);
    const monthly = await dbAll(`SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count FROM crime_reports GROUP BY month ORDER BY month DESC LIMIT 6`);

    res.json({
      success: true,
      stats: {
        totalReports: totalReports.count,
        resolved: resolved.count,
        pending: pending.count,
        officers: officers.count,
        citizens: citizens.count,
        crimeTypes,
        monthly
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch stats.' });
  }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'Server is running.', timestamp: new Date().toISOString() });
});

// ==================== SERVE FRONTEND ====================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});

// Start server
app.listen(PORT, () => {
  console.log(`============================================`);
  console.log(`  Crime Report Management System`);
  console.log(`  Server running on http://localhost:${PORT}`);
  console.log(`============================================`);
  console.log(`  API Base: http://localhost:${PORT}/api`);
  console.log(`  Frontend: http://localhost:${PORT}/`);
  console.log(`============================================`);
});

module.exports = app;
