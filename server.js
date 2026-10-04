const express = require('express');
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { MongoMemoryServer } = require('mongodb-memory-server');

const app = express();
const PORT = Number(process.env.PORT || 5000);
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const PRIVATE_FILES = path.join(__dirname, 'private_uploads');

app.disable('x-powered-by');
app.use(express.json({ limit: '7mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get(['/teacher/login', '/student/login'], (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  phone: { type: String, trim: true, maxlength: 30 },
  role: { type: String, enum: ['super_admin', 'admin', 'teacher', 'student'], default: 'student' },
  status: { type: String, enum: ['active', 'suspended'], default: 'active' },
  courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }],
}, { timestamps: true });

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 120 },
  level: { type: String, default: 'المستوى الأول', maxlength: 60 },
  description: { type: String, default: '', maxlength: 1200 },
  published: { type: Boolean, default: false },
  lessons: [{
    title: { type: String, required: true, maxlength: 120 },
    type: { type: String, enum: ['video', 'audio', 'pdf', 'practice'], default: 'video' },
    url: { type: String, default: '', maxlength: 1000 },
    duration: { type: String, default: '', maxlength: 30 },
  }],
  quizzes: [{
    title: { type: String, required: true, maxlength: 120 },
    questions: [{
      prompt: { type: String, required: true, maxlength: 500 },
      choices: [{ type: String, required: true, maxlength: 200 }],
      correctIndex: { type: Number, required: true, min: 0 },
    }],
  }],
}, { timestamps: true });

const paymentSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
  method: { type: String, enum: ['bankak', 'cash', 'other'], default: 'bankak' },
  transactionRef: { type: String, required: true, trim: true, maxlength: 100 },
  receiptAsset: { type: mongoose.Schema.Types.ObjectId, ref: 'Asset' },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

const progressSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
  lessonId: { type: mongoose.Schema.Types.ObjectId, required: true },
  completed: { type: Boolean, default: false },
}, { timestamps: true });
progressSchema.index({ student: 1, course: 1, lessonId: 1 }, { unique: true });

const quizAttemptSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
  quizId: { type: mongoose.Schema.Types.ObjectId, required: true },
  answers: [{ type: Number, required: true }],
  score: { type: Number, required: true },
  total: { type: Number, required: true },
}, { timestamps: true });

const attendanceSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  day: { type: String, required: true },
}, { timestamps: true });
attendanceSchema.index({ student: 1, day: 1 }, { unique: true });

const messageSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String, required: true, trim: true, maxlength: 1500 },
  response: { type: String, default: '', maxlength: 1500 },
  status: { type: String, enum: ['open', 'answered'], default: 'open' },
}, { timestamps: true });

const platformSettingsSchema = new mongoose.Schema({
  _id: { type: String, default: 'platform' },
  studentPortalOpen: { type: Boolean, default: false },
}, { timestamps: true });

const loginOtpSchema = new mongoose.Schema({
  challengeId: { type: String, required: true, unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  email: { type: String, required: true, lowercase: true },
  portal: { type: String, enum: ['teacher', 'student'], required: true },
  codeHash: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  attempts: { type: Number, default: 0, min: 0, max: 5 },
  usedAt: { type: Date },
}, { timestamps: true });
loginOtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
loginOtpSchema.index({ email: 1, createdAt: -1 });

const assetSchema = new mongoose.Schema({
  originalName: { type: String, required: true, maxlength: 180 },
  storageName: { type: String, required: true, unique: true },
  mimeType: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  purpose: { type: String, enum: ['receipt', 'lesson'], required: true },
  course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course' },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Course = mongoose.model('Course', courseSchema);
const Payment = mongoose.model('Payment', paymentSchema);
const Progress = mongoose.model('Progress', progressSchema);
const Asset = mongoose.model('Asset', assetSchema);
const QuizAttempt = mongoose.model('QuizAttempt', quizAttemptSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);
const Message = mongoose.model('Message', messageSchema);
const PlatformSettings = mongoose.model('PlatformSettings', platformSettingsSchema);
const LoginOtp = mongoose.model('LoginOtp', loginOtpSchema);

const LOGIN_OTP_TTL_MS = 10 * 60 * 1000;
const LOGIN_OTP_RESEND_DELAY_MS = 60 * 1000;
const LOGIN_OTP_MAX_ATTEMPTS = 5;
let mailTransporter;
let memoryMongoServer = null;

async function connectDatabase(options = {}) {
  const allowMemoryFallback = options.allowMemoryFallback ?? true;
  const connectOptions = { serverSelectionTimeoutMS: 5000 };

  if (process.env.MONGO_URI) {
    try {
      await mongoose.connect(process.env.MONGO_URI, connectOptions);
      return { uri: process.env.MONGO_URI, memoryServer: null };
    } catch (error) {
      if (!allowMemoryFallback) throw error;
      console.warn('MongoDB connection failed. Starting the in-memory fallback database instead.');
    }
  } else if (!allowMemoryFallback) {
    throw new Error('Set MONGO_URI and TOKEN_SECRET before starting the server.');
  }

  try {
    memoryMongoServer = await MongoMemoryServer.create({ binary: { version: '7.0.14' } });
    const uri = memoryMongoServer.getUri();
    process.env.MONGO_URI = uri;
    await mongoose.connect(uri, connectOptions);
    return { uri, memoryServer: memoryMongoServer };
  } catch (error) {
    throw new Error(`Unable to start the in-memory MongoDB fallback: ${error.message}`);
  }
}

async function closeDatabase() {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
  if (memoryMongoServer) {
    await memoryMongoServer.stop();
    memoryMongoServer = null;
  }
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

async function requireAuth(req, res, next) {
  const cookieHeader = req.headers.cookie || '';
  const token = cookieHeader.split(';').map(part => part.trim()).find(part => part.startsWith('lms_session='))?.slice('lms_session='.length);
  if (!token) return res.status(401).json({ message: 'يرجى تسجيل الدخول' });
  try {
    req.auth = jwt.verify(token, TOKEN_SECRET);
  } catch {
    res.clearCookie('lms_session');
    return res.status(401).json({ message: 'انتهت الجلسة، يرجى تسجيل الدخول مجدداً' });
  }
  try {
    req.user = await User.findById(req.auth.id);
    if (!req.user || req.user.status !== 'active') {
      res.clearCookie('lms_session');
      return res.status(403).json({ message: 'الحساب موقوف أو غير متاح' });
    }
    if (req.user.role === 'student') {
      const settings = await getPlatformSettings();
      if (!settings.studentPortalOpen) {
        res.clearCookie('lms_session');
        return res.status(403).json({ message: 'بوابة الطلاب مغلقة حالياً. تواصل مع الأستاذ.' });
      }
    } else if (!['teacher', 'super_admin'].includes(req.user.role)) {
      res.clearCookie('lms_session');
      return res.status(403).json({ message: 'عذراً، هذه البوابة مخصصة للأستاذ/المدير فقط. بوابة الطلاب مغلقة حالياً.' });
    }
    req.auth.role = req.user.role;
    next();
  } catch (error) {
    next(error);
  }
}

function requireAdmin(req, res, next) {
  if (!['teacher', 'super_admin'].includes(req.auth.role)) return res.status(403).json({ message: 'هذه الصلاحية للأستاذ فقط' });
  next();
}

function requireSuperAdmin(req, res, next) {
  if (req.auth.role !== 'super_admin' || req.user.email !== 'sameyasen04@gmail.com') {
    return res.status(403).json({ message: 'هذه الصلاحية للمدير العام المحدد فقط' });
  }
  next();
}

async function currentUser(req) {
  return req.user;
}

async function canAccessCourse(user, course) {
  return ['teacher', 'super_admin'].includes(user.role) || (user.status === 'active' && course.published && user.courses.some(id => id.equals(course._id)));
}

async function getPlatformSettings() {
  return PlatformSettings.findByIdAndUpdate(
    'platform',
    { $setOnInsert: { studentPortalOpen: false } },
    { new: true, upsert: true, setDefaultsOnInsert: true },
  );
}

async function seedSuperAdmin(password = process.env.SUPER_ADMIN_PASSWORD) {
  if (!password || password.length < 10) throw new Error('SUPER_ADMIN_PASSWORD must be at least 10 characters long.');
  const email = 'sameyasen04@gmail.com';
  const passwordHash = await bcrypt.hash(password, 12);
  await User.findOneAndUpdate(
    { email },
    {
      $set: {
        fullName: process.env.SUPER_ADMIN_NAME || 'المدير العام',
        email,
        passwordHash,
        role: 'super_admin',
        status: 'active',
      },
      $setOnInsert: { courses: [] },
    },
    { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
  );
}

function getMailTransporter() {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) return null;
  if (!mailTransporter) {
    mailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD.replace(/\s/g, '') },
    });
  }
  return mailTransporter;
}

function hashLoginOtp(email, challengeId, code) {
  return crypto.createHmac('sha256', TOKEN_SECRET).update(`${email}:${challengeId}:${code}`).digest('hex');
}

function maskEmail(email) {
  const [name, domain] = email.split('@');
  return `${name.slice(0, 1)}${'*'.repeat(Math.max(2, Math.min(name.length - 1, 6)))}@${domain}`;
}

function setLoginSession(user, res) {
  const token = jwt.sign({ id: user.id, role: user.role }, TOKEN_SECRET, { expiresIn: '12h' });
  res.cookie('lms_session', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 12 * 60 * 60 * 1000,
  });
  res.json({ user: { id: user.id, fullName: user.fullName, role: user.role } });
}

function otpEmailHtml(code) {
  return `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"></head><body style="margin:0;background:#f3f6f2;font-family:Tahoma,Arial,sans-serif;color:#173a30"><div style="max-width:520px;margin:32px auto;padding:32px;background:#fff;border:1px solid #dfe8df;border-radius:8px"><p style="margin:0 0 12px;color:#126b51;font-size:13px;font-weight:bold">تعلم الإنجليزية معنا</p><h1 style="margin:0 0 12px;font-size:24px">رمز تسجيل الدخول</h1><p style="line-height:1.8;color:#52645d">استخدم الرمز التالي لإكمال تسجيل الدخول. الرمز صالح لمدة 10 دقائق ولا تشاركه مع أي شخص.</p><div dir="ltr" style="margin:24px 0;padding:18px;background:#edf5ef;border-radius:6px;text-align:center;font-size:32px;letter-spacing:8px;font-weight:bold;color:#126b51">${code}</div><p style="margin:0;color:#7b8983;font-size:12px">إذا لم تطلب هذا الرمز، يمكنك تجاهل الرسالة.</p></div></body></html>`;
}

function isSafeLessonUrl(value) {
  if (!value) return true;
  if (value.startsWith('/api/files/')) return true;
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

app.get('/api/health', (req, res) => res.json({ status: mongoose.connection.readyState === 1 ? 'ok' : 'database-unavailable' }));

app.get('/api/portal/status', asyncRoute(async (req, res) => {
  const settings = await getPlatformSettings();
  res.json({ studentPortalOpen: settings.studentPortalOpen });
}));

app.post('/api/auth/request-otp', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const portal = req.body.portal;
  if (!['teacher', 'student'].includes(portal)) return res.status(400).json({ message: 'اختر بوابة تسجيل الدخول أولاً.' });
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ message: 'بيانات الدخول غير صحيحة' });
  }
  if (user.status !== 'active') return res.status(403).json({ message: 'الحساب موقوف حالياً، تواصل مع الأستاذ' });
  if (portal === 'teacher' && !['teacher', 'super_admin'].includes(user.role)) {
    return res.status(403).json({ message: 'هذه البوابة مخصصة للأستاذ والمدير فقط.' });
  }
  if (portal === 'student' && user.role !== 'student') {
    return res.status(403).json({ message: 'استخدم بوابة الأستاذ أو المدير لهذا الحساب.' });
  }
  if (portal === 'student') {
    const settings = await getPlatformSettings();
    if (!settings.studentPortalOpen) return res.status(403).json({ message: 'بوابة الطلاب مغلقة حالياً. تواصل مع الأستاذ.' });
  }
  const transporter = getMailTransporter();
  if (!transporter) return res.status(503).json({ message: 'خدمة البريد غير مهيأة حالياً. تواصل مع مدير المنصة.' });
  const now = new Date();
  const recentlyIssued = await LoginOtp.exists({ email, createdAt: { $gte: new Date(now.getTime() - LOGIN_OTP_RESEND_DELAY_MS) } });
  if (recentlyIssued) return res.status(429).json({ message: 'انتظر دقيقة قبل طلب رمز جديد.' });

  const challengeId = crypto.randomUUID();
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  await LoginOtp.deleteMany({ email });
  await LoginOtp.create({
    challengeId,
    user: user._id,
    email,
    portal,
    codeHash: hashLoginOtp(email, challengeId, code),
    expiresAt: new Date(now.getTime() + LOGIN_OTP_TTL_MS),
  });
  try {
    await transporter.sendMail({
      from: process.env.GMAIL_FROM || process.env.GMAIL_USER,
      to: user.email,
      subject: 'رمز تسجيل الدخول | تعلم الإنجليزية معنا',
      text: `رمز تسجيل الدخول هو ${code}. صالح لمدة 10 دقائق. لا تشاركه مع أي شخص.`,
      html: otpEmailHtml(code),
    });
  } catch (error) {
    await LoginOtp.deleteOne({ challengeId });
    console.error(`OTP email delivery failed: ${error.message}`);
    return res.status(503).json({ message: 'تعذر إرسال البريد الآن. حاول لاحقاً.' });
  }
  res.json({ challengeId, maskedEmail: maskEmail(user.email), expiresInSeconds: LOGIN_OTP_TTL_MS / 1000 });
}));

app.post('/api/auth/verify-otp', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const challengeId = String(req.body.challengeId || '');
  const code = String(req.body.code || '');
  if (!/^\d{6}$/.test(code) || !challengeId) return res.status(400).json({ message: 'أدخل رمزاً صحيحاً من 6 أرقام.' });

  const challenge = await LoginOtp.findOne({ challengeId, email });
  if (!challenge || !['teacher', 'student'].includes(challenge.portal) || challenge.usedAt || challenge.attempts >= LOGIN_OTP_MAX_ATTEMPTS) {
    return res.status(400).json({ message: 'الرمز غير صالح أو انتهت صلاحيته. اطلب رمزاً جديداً.' });
  }
  if (challenge.expiresAt <= new Date()) {
    await LoginOtp.deleteOne({ _id: challenge._id });
    return res.status(410).json({ message: 'انتهت صلاحية الرمز. اطلب رمزاً جديداً.' });
  }

  const submittedHash = Buffer.from(hashLoginOtp(email, challengeId, code), 'hex');
  const storedHash = Buffer.from(challenge.codeHash, 'hex');
  if (submittedHash.length !== storedHash.length || !crypto.timingSafeEqual(submittedHash, storedHash)) {
    await LoginOtp.findOneAndUpdate(
      { _id: challenge._id, attempts: { $lt: LOGIN_OTP_MAX_ATTEMPTS } },
      { $inc: { attempts: 1 } },
      { new: true },
    );
    return res.status(400).json({ message: 'رمز التحقق غير صحيح.' });
  }

  const consumed = await LoginOtp.updateOne(
    { _id: challenge._id, usedAt: { $exists: false }, expiresAt: { $gt: new Date() }, attempts: { $lt: LOGIN_OTP_MAX_ATTEMPTS } },
    { $set: { usedAt: new Date() } },
  );
  if (consumed.modifiedCount !== 1) return res.status(410).json({ message: 'انتهت صلاحية الرمز أو استُخدم مسبقاً.' });
  const user = await User.findById(challenge.user);
  if (!user || user.status !== 'active') return res.status(403).json({ message: 'الحساب موقوف أو غير متاح.' });
  if (challenge.portal === 'teacher' && !['teacher', 'super_admin'].includes(user.role)) {
    return res.status(403).json({ message: 'هذه البوابة مخصصة للأستاذ والمدير فقط.' });
  }
  if (challenge.portal === 'student' && user.role !== 'student') {
    return res.status(403).json({ message: 'استخدم بوابة الأستاذ أو المدير لهذا الحساب.' });
  }
  if (challenge.portal === 'student') {
    const settings = await getPlatformSettings();
    if (!settings.studentPortalOpen) return res.status(403).json({ message: 'بوابة الطلاب مغلقة حالياً. تواصل مع الأستاذ.' });
    const day = new Date().toISOString().slice(0, 10);
    await Attendance.updateOne({ student: user._id, day }, { $setOnInsert: { student: user._id, day } }, { upsert: true });
  }
  setLoginSession(user, res);
}));

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('lms_session', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
  res.json({ message: 'تم تسجيل الخروج' });
});

app.get('/api/auth/me', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  if (!user || user.status !== 'active') return res.status(403).json({ message: 'الحساب غير متاح' });
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, role: user.role, status: user.status } });
}));

app.get('/api/admin/platform-settings', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const settings = await getPlatformSettings();
  res.json({ studentPortalOpen: settings.studentPortalOpen });
}));

app.patch('/api/admin/platform-settings', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  if (typeof req.body.studentPortalOpen !== 'boolean') return res.status(400).json({ message: 'حالة بوابة الطلاب غير صالحة' });
  const settings = await PlatformSettings.findByIdAndUpdate(
    'platform',
    { $set: { studentPortalOpen: req.body.studentPortalOpen } },
    { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true },
  );
  res.json({ studentPortalOpen: settings.studentPortalOpen });
}));

app.get('/api/courses', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  const isInstructor = ['teacher', 'super_admin'].includes(user.role);
  const filter = isInstructor ? {} : { _id: { $in: user.courses }, published: true };
  const query = Course.find(filter).sort({ createdAt: -1 });
  if (!isInstructor) query.select('-quizzes.questions.correctIndex');
  const courses = await query;
  res.json({ courses });
}));

app.get('/api/catalog', requireAuth, asyncRoute(async (req, res) => {
  const courses = await Course.find({ published: true }).select('title level description lessons.title lessons.type').sort({ createdAt: -1 });
  res.json({ courses });
}));

app.get('/api/courses/:courseId', requireAuth, asyncRoute(async (req, res) => {
  const [user, course] = await Promise.all([currentUser(req), Course.findById(req.params.courseId)]);
  if (!course) return res.status(404).json({ message: 'الدورة غير موجودة' });
  if (!(await canAccessCourse(user, course))) return res.status(403).json({ message: 'لا تملك صلاحية الوصول لهذه الدورة' });
  const progress = await Progress.find({ student: user._id, course: course._id });
  const courseData = course.toObject();
  if (!['teacher', 'super_admin'].includes(user.role)) {
    courseData.quizzes = courseData.quizzes.map(quiz => ({
      ...quiz,
      questions: quiz.questions.map(({ correctIndex, ...question }) => question),
    }));
  }
  res.json({ course: courseData, progress });
}));

app.post('/api/admin/students', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const { fullName, email, password, phone, courses = [] } = req.body;
  if (!fullName || !email || !password || String(password).length < 10) {
    return res.status(400).json({ message: 'أدخل الاسم والبريد وكلمة مرور من 10 أحرف على الأقل' });
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const student = await User.create({ fullName, email, passwordHash, phone, courses, role: 'student' });
  res.status(201).json({ student: { id: student.id, fullName: student.fullName, email: student.email, status: student.status } });
}));

app.post('/api/admin/teachers', requireAuth, requireSuperAdmin, asyncRoute(async (req, res) => {
  const { fullName, email, password, phone } = req.body;
  if (!fullName || !email || !password || String(password).length < 10) {
    return res.status(400).json({ message: 'أدخل الاسم والبريد وكلمة مرور من 10 أحرف على الأقل' });
  }
  const teacher = await User.create({
    fullName, email, phone, role: 'teacher',
    passwordHash: await bcrypt.hash(password, 12),
  });
  res.status(201).json({ teacher: { id: teacher.id, fullName: teacher.fullName, email: teacher.email, role: teacher.role } });
}));

app.get('/api/admin/students', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const students = await User.find({ role: 'student' }).select('-passwordHash').populate('courses', 'title level');
  res.json({ students });
}));

app.patch('/api/admin/students/:studentId/status', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  if (!['active', 'suspended'].includes(req.body.status)) return res.status(400).json({ message: 'حالة الحساب غير صالحة' });
  const student = await User.findOneAndUpdate({ _id: req.params.studentId, role: 'student' }, { status: req.body.status }, { new: true }).select('-passwordHash');
  if (!student) return res.status(404).json({ message: 'الطالب غير موجود' });
  res.json({ student });
}));

app.post('/api/admin/courses', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const { title, level, description, published } = req.body;
  const course = await Course.create({ title, level, description, published });
  res.status(201).json({ course });
}));

app.put('/api/admin/courses/:courseId', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const updates = {};
  for (const field of ['title', 'level', 'description', 'published']) {
    if (Object.hasOwn(req.body, field)) updates[field] = req.body[field];
  }
  const course = await Course.findByIdAndUpdate(req.params.courseId, updates, { new: true, runValidators: true });
  if (!course) return res.status(404).json({ message: 'الدورة غير موجودة' });
  res.json({ course });
}));

app.post('/api/admin/courses/:courseId/lessons', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  if (!isSafeLessonUrl(String(req.body.url || ''))) return res.status(400).json({ message: 'استخدم رابط HTTPS أو ملفاً مرفوعاً إلى المنصة' });
  const course = await Course.findById(req.params.courseId);
  if (!course) return res.status(404).json({ message: 'الدورة غير موجودة' });
  course.lessons.push(req.body);
  await course.save();
  res.status(201).json({ course });
}));

app.post('/api/admin/courses/:courseId/quizzes', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const { title, questions } = req.body;
  if (!title || !Array.isArray(questions) || questions.length === 0 || questions.length > 30) {
    return res.status(400).json({ message: 'أدخل عنوان الاختبار من سؤال إلى 30 سؤالاً' });
  }
  const validQuestions = questions.every(question => question.prompt && Array.isArray(question.choices)
    && question.choices.length >= 2 && question.choices.length <= 6
    && Number.isInteger(question.correctIndex) && question.correctIndex >= 0 && question.correctIndex < question.choices.length);
  if (!validQuestions) return res.status(400).json({ message: 'تحقق من نصوص الأسئلة والخيارات والإجابة الصحيحة' });
  const course = await Course.findById(req.params.courseId);
  if (!course) return res.status(404).json({ message: 'الدورة غير موجودة' });
  course.quizzes.push({ title, questions });
  await course.save();
  res.status(201).json({ quiz: course.quizzes.at(-1) });
}));

app.post('/api/courses/:courseId/quizzes/:quizId/submit', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  const course = await Course.findById(req.params.courseId);
  if (!course || !(await canAccessCourse(user, course))) return res.status(403).json({ message: 'لا تملك صلاحية الوصول لهذا الاختبار' });
  const quiz = course.quizzes.id(req.params.quizId);
  if (!quiz) return res.status(404).json({ message: 'الاختبار غير موجود' });
  const answers = req.body.answers;
  if (!Array.isArray(answers) || answers.length !== quiz.questions.length || answers.some((answer, index) => !Number.isInteger(answer) || answer < 0 || answer >= quiz.questions[index].choices.length)) {
    return res.status(400).json({ message: 'أجب عن جميع أسئلة الاختبار' });
  }
  const score = quiz.questions.reduce((sum, question, index) => sum + (question.correctIndex === answers[index] ? 1 : 0), 0);
  const attempt = await QuizAttempt.create({ student: user._id, course: course._id, quizId: quiz._id, answers, score, total: quiz.questions.length });
  res.json({ score, total: quiz.questions.length, percentage: Math.round(score / quiz.questions.length * 100), attemptId: attempt.id });
}));

app.post('/api/payments', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  const { courseId, method = 'bankak', transactionRef, receiptAsset } = req.body;
  const course = await Course.findById(courseId);
  if (!course || !course.published) return res.status(404).json({ message: 'الدورة غير متاحة للتسجيل' });
  if (!transactionRef) return res.status(400).json({ message: 'أدخل رقم العملية أو مرجع التحويل' });
  if (receiptAsset) {
    const asset = await Asset.findOne({ _id: receiptAsset, owner: user._id, purpose: 'receipt' });
    if (!asset) return res.status(400).json({ message: 'ملف الإيصال غير صالح' });
  }
  const payment = await Payment.create({ student: user._id, course: course._id, method, transactionRef, receiptAsset });
  res.status(201).json({ payment: { id: payment.id, status: payment.status } });
}));

app.get('/api/admin/payments', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const payments = await Payment.find().sort({ createdAt: -1 }).populate('student', 'fullName email phone').populate('course', 'title').populate('receiptAsset', 'originalName');
  res.json({ payments });
}));

app.patch('/api/admin/payments/:paymentId', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ message: 'قرار المراجعة غير صالح' });
  const payment = await Payment.findById(req.params.paymentId);
  if (!payment) return res.status(404).json({ message: 'طلب الدفع غير موجود' });
  payment.status = status;
  payment.reviewedBy = req.auth.id;
  await payment.save();
  if (status === 'approved') await User.updateOne({ _id: payment.student }, { $addToSet: { courses: payment.course } });
  res.json({ payment: { id: payment.id, status: payment.status } });
}));

app.get('/api/progress', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  const progress = await Progress.find({ student: user._id }).populate('course', 'title level');
  res.json({ progress });
}));

app.get('/api/admin/progress', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const progress = await Progress.find().sort({ updatedAt: -1 }).populate('student', 'fullName').populate('course', 'title lessons');
  res.json({ progress: progress.map(item => ({
    ...item.toObject(),
    lessonTitle: item.course?.lessons.id(item.lessonId)?.title || 'درس محذوف',
  })) });
}));

app.get('/api/admin/attendance', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const attendance = await Attendance.find().sort({ day: -1 }).limit(100).populate('student', 'fullName email');
  res.json({ attendance });
}));

app.get('/api/admin/quiz-attempts', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const attempts = await QuizAttempt.find().sort({ createdAt: -1 }).limit(200).populate('student', 'fullName email').populate('course', 'title quizzes.title');
  res.json({ attempts: attempts.map(attempt => ({
    ...attempt.toObject(),
    quizTitle: attempt.course?.quizzes.id(attempt.quizId)?.title || 'اختبار محذوف',
  })) });
}));

app.get('/api/messages', requireAuth, asyncRoute(async (req, res) => {
  const filter = ['teacher', 'super_admin'].includes(req.user.role) ? {} : { student: req.user._id };
  const messages = await Message.find(filter).sort({ createdAt: -1 }).populate('student', 'fullName email');
  res.json({ messages });
}));

app.post('/api/messages', requireAuth, asyncRoute(async (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'إرسال هذه الرسالة متاح للطلاب' });
  const message = String(req.body.message || '').trim();
  if (!message || message.length > 1500) return res.status(400).json({ message: 'اكتب رسالة من 1 إلى 1500 حرف' });
  const item = await Message.create({ student: req.user._id, message });
  res.status(201).json({ message: item });
}));

app.patch('/api/messages/:messageId', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const response = String(req.body.response || '').trim();
  if (!response || response.length > 1500) return res.status(400).json({ message: 'اكتب رداً من 1 إلى 1500 حرف' });
  const item = await Message.findByIdAndUpdate(req.params.messageId, { response, status: 'answered' }, { new: true, runValidators: true }).populate('student', 'fullName email');
  if (!item) return res.status(404).json({ message: 'الرسالة غير موجودة' });
  res.json({ message: item });
}));

app.put('/api/progress/:courseId/:lessonId', requireAuth, asyncRoute(async (req, res) => {
  const [user, course] = await Promise.all([currentUser(req), Course.findById(req.params.courseId)]);
  if (!course || !(await canAccessCourse(user, course))) return res.status(403).json({ message: 'لا تملك صلاحية الوصول لهذا الدرس' });
  if (!course.lessons.id(req.params.lessonId)) return res.status(404).json({ message: 'الدرس غير موجود' });
  const progress = await Progress.findOneAndUpdate(
    { student: user._id, course: course._id, lessonId: req.params.lessonId },
    { completed: Boolean(req.body.completed) },
    { upsert: true, new: true, runValidators: true },
  );
  res.json({ progress });
}));

app.post('/api/uploads', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  const { name, mimeType, data, purpose, courseId } = req.body;
  const allowedTypes = new Set(['application/pdf', 'image/jpeg', 'image/png', 'audio/mpeg', 'audio/mp4']);
  if (!allowedTypes.has(mimeType) || !['receipt', 'lesson'].includes(purpose) || !data) {
    return res.status(400).json({ message: 'نوع الملف أو الغرض غير مدعوم' });
  }
  if (purpose === 'lesson' && !['teacher', 'super_admin'].includes(user.role)) return res.status(403).json({ message: 'رفع الدروس للأستاذ فقط' });
  if (purpose === 'lesson' && !(await Course.exists({ _id: courseId }))) return res.status(404).json({ message: 'الدورة غير موجودة' });
  const buffer = Buffer.from(String(data), 'base64');
  if (!buffer.length || buffer.length > 5 * 1024 * 1024) return res.status(413).json({ message: 'الحد الأقصى لحجم الملف 5 ميغابايت' });
  await fs.mkdir(PRIVATE_FILES, { recursive: true });
  const extension = path.extname(String(name || '')).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 10);
  const storageName = `${crypto.randomUUID()}${extension}`;
  await fs.writeFile(path.join(PRIVATE_FILES, storageName), buffer, { flag: 'wx' });
  const asset = await Asset.create({ originalName: String(name || 'file').slice(0, 180), storageName, mimeType, owner: user._id, purpose, course: purpose === 'lesson' ? courseId : undefined });
  res.status(201).json({ asset: { id: asset.id, name: asset.originalName } });
}));

app.get('/api/files/:assetId', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  const asset = await Asset.findById(req.params.assetId);
  if (!asset) return res.status(404).json({ message: 'الملف غير موجود' });
  let permitted = ['teacher', 'super_admin'].includes(user.role) || asset.owner.equals(user._id);
  if (!permitted && asset.purpose === 'lesson' && user.status === 'active') {
    const course = await Course.findById(asset.course);
    permitted = Boolean(course && await canAccessCourse(user, course));
  }
  if (!permitted) return res.status(403).json({ message: 'لا تملك صلاحية تنزيل هذا الملف' });
  res.type(asset.mimeType).download(path.join(PRIVATE_FILES, asset.storageName), asset.originalName);
}));

app.use((error, req, res, next) => {
  console.error(error);
  if (error.code === 11000) return res.status(409).json({ message: 'البريد الإلكتروني مسجل مسبقاً' });
  if (error.name === 'ValidationError' || error.name === 'CastError') return res.status(400).json({ message: 'البيانات المدخلة غير صالحة' });
  res.status(mongoose.connection.readyState === 1 ? 500 : 503).json({ message: mongoose.connection.readyState === 1 ? 'حدث خطأ داخلي' : 'قاعدة البيانات غير متصلة' });
});

async function start() {
  if (!TOKEN_SECRET) throw new Error('Set TOKEN_SECRET before starting the server.');
  await connectDatabase();
  const bootstrapPassword = process.env.SUPER_ADMIN_PASSWORD || process.env.ADMIN_PASSWORD;
  if (bootstrapPassword) await seedSuperAdmin(bootstrapPassword);
  const email = 'sameyasen04@gmail.com';
  if (!bootstrapPassword) {
    const existing = await User.findOne({ email });
    if (!existing || existing.role !== 'super_admin' || existing.status !== 'active') {
      console.warn(`Set SUPER_ADMIN_PASSWORD to create or enable the instructor account ${email}.`);
    }
  }
  app.listen(PORT, () => console.log(`Learn English With Us is running at http://localhost:${PORT}`));
  process.on('SIGINT', async () => {
    await closeDatabase();
    process.exit(0);
  });
}

if (require.main === module) {
  start().catch(error => {
    console.error(`Startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { app, User, seedSuperAdmin, connectDatabase, closeDatabase };