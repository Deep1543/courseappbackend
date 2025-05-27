import express from 'express';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import mysql from 'mysql2';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import nodemailer from 'nodemailer';
import cron from 'node-cron';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import axios from 'axios';


const app = express();
const port = 5000;
const jwtSecret = 'your_jwt_secret';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(bodyParser.json());

// MySQL Connection Pool
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'deep1543',
    database: 'courseapp',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


const handleDbError = (error, res) => {
    console.error('Database error:', error);
    res.status(500).json({ message: 'Internal Server Error', error: error.message });
};

db.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Database connected successfully');
    connection.release();
});



const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'deepjadav4649@gmail.com',
    pass: 'rbsjfoldxfdnpkyv',
  },
  tls: {
    rejectUnauthorized: false,  // Disable certificate validation
  },
});



const sendRenewalNotification = (purchase) => {
    const { email, title, end_date } = purchase;

    const mailOptions = {
        from: 'deepjadav1543@gmail.com',  // Sender email
        to: email,  // Use dynamic email from the purchase
        subject: `Your course ${title} is about to expire!`,
        text: `Dear user, your course "${title}" will expire on ${end_date}. Please renew your subscription to continue.`,
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.error('Error sending email:', err);
            return;  // Ensure we return after error logging
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
};

// FAQ responses
const chatbotResponses = {
    'hi': 'Hello! How can I assist you today?',
    'help': 'Sure! Please ask your query.',
    'what courses are available': 'We offer a variety of online courses including Web Development, Data Science, and AI/ML. You can view all courses on our website.',
    'how can i enroll in a course': 'To enroll in a course, please visit the course details page and click on the "Enroll Now" button.',
    'what is the cost of the courses': 'The cost of courses varies. Please check the course details for specific pricing information.',
    'what is the duration of the courses': 'Course durations vary from a few weeks to several months. You can find the duration in the course details.',
    'how do i contact support': 'You can contact us at support@scriptindia.in for any questions or issues.',
    'is there any certificate provided': 'Yes, we provide a certificate upon successful completion of the course.',
    'can i pay in installments': 'Yes, we offer flexible payment options, including installments. Please visit our payment page for more details.',
    'what is the refund policy': 'We offer a 30-day money-back guarantee. If you are not satisfied with the course, you can request a refund within 30 days of purchase.',
    'courses available for beginners': 'We have several beginner-friendly courses in Web Development and Data Science. Check our course catalog for more details.',
};


// Handle chatbot message
app.post('/chatbot', (req, res) => {
  const { message } = req.body;
  const response = chatbotResponses[message] || "Sorry, I didn't understand that. Please try again.";
  res.json({ response });
});

dotenv.config();

// console.log("Loaded API Key:", process.env.GEMINI_API_KEY);
// const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// if (!GEMINI_API_KEY) {
//     console.error("❌ GEMINI_API_KEY is missing. Check your .env file!");
//     process.exit(1);
// }

// app.post('/chatbot', async (req, res) => {
//     try {
//         const { message } = req.body;

//         const response = await axios.post(
//             `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro:generateContent?key=${GEMINI_API_KEY}`,
//             {
//                 contents: [{ parts: [{ text: message }] }]
//             },
//             {
//                 headers: {
//                     'Content-Type': 'application/json'
//                 }
//             }
//         );

//         const reply = response.data.candidates?.[0]?.content?.parts?.[0]?.text || "Sorry, I didn't understand that.";
//         res.json({ response: reply });
//     } catch (error) {
//         console.error('Error in chatbot:', error.response?.data || error.message);
//         res.status(500).json({ response: "Sorry, something went wrong." });
//     }
// });

// Webhook to handle incoming messages from WhatsApp
app.post('/webhook', async (req, res) => {
    console.log("✅ Webhook called");
    console.log("📦 Received body:", JSON.stringify(req.body, null, 2));

    try {
        // Extract the message from the request body and log it for inspection
        const message = req.body?.entry?.[0]?.changes?.[0]?.value?.messages?.[0];
        console.log("Message received:", message); // Log the full message

        const phoneNumberId = req.body?.entry?.[0]?.changes?.[0]?.value?.metadata?.phone_number_id;
        const from = message?.from;
        const text = message?.text?.body;

        if (text && from) {
            console.log("📨 Message from user:", from);
            console.log("📝 Message text:", text);

            // 1. Save the user's message to the MySQL database
            const sql = 'INSERT INTO whatsapp_messages (sender, user_message) VALUES (?, ?)';
            db.query(sql, [from, text], (err, result) => {
                if (err) {
                    console.error("❌ MySQL Insert Error:", err.message);
                    res.status(500).send("Error inserting message into DB.");
                    return;
                } else {
                    console.log("✅ Message stored in DB with ID:", result.insertId);
                }
            });

            // 2. Check for common greetings and respond accordingly
            let reply;
            if (["hii", "hello", "hey", "hi"].includes(text.toLowerCase())) {
                reply = "Hello! How can I assist you today?";
            } else {
                // Get the chatbot's response using the Gemini API
                const geminiResponse = await axios.post(
                    `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro:generateContent?key=${GEMINI_API_KEY}`,
                    
                    { contents: [{ parts: [{ text }] }] },
                    { headers: { 'Content-Type': 'application/json' } }
                );

                reply = geminiResponse.data.candidates?.[0]?.content?.parts?.[0]?.text || "Sorry, I didn't understand that.";
            }

            console.log("🤖 Chatbot reply:", reply);

            // 3. Send the chatbot's reply back to the user on WhatsApp
            const whatsappResponse = await axios.post(
                `https://graph.facebook.com/v18.0/${phoneNumberId}/messages`,
                {
                    messaging_product: "whatsapp",
                    to: from,
                    text: { body: reply }
                },
                {
                    headers: {
                        Authorization: `Bearer ${process.env.WHATSAPP_TOKEN}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            console.log("✅ Message sent to WhatsApp:", whatsappResponse.data);
        } else {
            console.log("⚠️ No valid text message or sender found.");
        }

        res.sendStatus(200);
    } catch (error) {
        console.error("❌ Webhook Error:", error.response?.data || error.message);
        res.sendStatus(500);
    }
});





// A separate webhook endpoint that might be needed for saving messages to MySQL directly
app.post('/whatsapp/webhook', (req, res) => {
    console.log("✅ /whatsapp/webhook called");

    // Extract data from the request body
    const { sender, message } = req.body; // Assuming these fields exist in the payload
    const botReply = "Your bot reply here"; // Set your bot's reply here (or retrieve dynamically)

    // Insert message into MySQL
    const query = 'INSERT INTO whatsapp_messages (sender, user_message, bot_reply) VALUES (?, ?, ?)';
    db.query(query, [sender, message, botReply], (err, result) => {
        if (err) {
            console.error('❌ MySQL Insert Error:', err);
            return res.status(500).json({ error: 'Error saving message' });
        }
        console.log('✅ Message saved to MySQL');
        res.status(200).json({ message: 'Message saved successfully' });
    });
});

// Webhook for Facebook verification (to set up webhook)
app.get('/webhook', (req, res) => {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    console.log("Mode:", mode);  // This should be "subscribe"
    console.log("Token:", token);  // This should match your verify token
    console.log("Challenge:", challenge);  // This is the challenge to send back

    // Check if the token matches your WhatsApp verification token
    if (mode === "subscribe" && token === process.env.VERIFY_TOKEN) {
        res.status(200).send(challenge);  // Respond with challenge for verification
    } else {
        console.log("❌ Token mismatch or error");
        res.sendStatus(403);  // Forbidden if tokens don't match
    }
});




app.get('/messages', (req, res) => {
    const sql = 'SELECT * FROM whatsapp_messages ORDER BY timestamp DESC';
    db.query(sql, (err, results) => {
        if (err) {
            console.error("❌ Error fetching messages:", err.message);
            return res.status(500).json({ error: 'Error fetching messages' });
        }
        res.status(200).json({ messages: results });
    });
});





// Token Authentication Middleware
// const authenticateToken = (req, res, next) => {
//     const authHeader = req.headers['authorization'];
//     const token = authHeader && authHeader.split(' ')[1];
//     if (!token) {
//         console.log('Token missing in the request header');
//         return res.status(401).json({ message: 'Token is required' });
//     }

//     jwt.verify(token, process.env.JWT_SECRET || jwtSecret, (err, user) => {
//         if (err) {
//             console.log('Invalid or expired token:', err.message);
//             return res.status(403).json({ message: 'Invalid token' });
//         }
//         console.log('Decoded user:', user);
//         req.user = user;
//         next();
//     });
// };

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token
    if (!token) {
        return res.status(401).json({ message: 'Token is required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user; // Assign the user from the token
        next();
    });
};


// Admin Verification Middleware
const verifyAdmin = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        console.log('Token missing');
        return res.status(401).json({ message: 'Unauthorized: Token missing' });
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        console.log('Decoded token:', decoded);
        if (decoded.role !== 'admin') {
            console.log('Role mismatch. Required: admin, Found:', decoded.role);
            return res.status(403).json({ message: 'Forbidden: Admin access required' });
        }
        next();
    } catch (error) {
        console.log('Token verification error:', error.message);
        return res.status(401).json({ message: 'Invalid token' });
    }
};
app.post('/store-conversation', (req, res) => {  
  const { userQuestion, chatbotReply } = req.body;
  const token = req.headers['authorization']?.split(' ')[1]; // Get token from header

  // Check if token is provided
  if (!token) {
    return res.status(401).json({ message: 'Authorization token is required' });
  }

  try {
    // Verify and decode the token using your JWT secret
    const decoded = jwt.verify(token, jwtSecret);  // Use your JWT secret here
    const userId = decoded.id;  // Assuming the token contains `id`
    const userRole = decoded.role; // Assuming the token contains `role`

    if (!userId) {
      return res.status(400).json({ message: 'User ID not found in token' });
    }

    // Insert conversation into the database
    const query = 'INSERT INTO chatbot_conversations (user_id, user_question, chatbot_reply) VALUES (?, ?, ?)';
    db.query(query, [userId, userQuestion, chatbotReply], (err, result) => {
      if (err) {
        console.error('Error inserting conversation:', err);
        return res.status(500).json({ message: 'Failed to store conversation' });
      }

      // Success response
      res.status(200).json({ message: 'Conversation stored successfully' });
    });
  } catch (error) {
    console.error('Error decoding token:', error);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
});
const __dirname = path.resolve();

// Define upload directories
const uploadDirs = {
    profile: path.join(__dirname, 'uploads', 'profile_images'),
    course: path.join(__dirname, 'uploads', 'course_images'),
};

// Ensure directories exist
Object.values(uploadDirs).forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        let uploadPath;

        // Fix: Ensure course images go to the right folder
        if (req.originalUrl.includes('/courses')) {
            uploadPath = uploadDirs.course;  // Correct directory
        } else {
            uploadPath = uploadDirs.profile; // Default to profile images
        }

        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        const ext = path.extname(file.originalname);
        const sanitizedFilename = file.originalname.replace(/\s+/g, '_');
        cb(null, `${timestamp}_${sanitizedFilename}`);
    },
});


const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
    fileFilter: (req, file, cb) => {
        if (!['.jpg', '.jpeg', '.png'].includes(path.extname(file.originalname).toLowerCase())) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    },
});

// Serve Static Files
app.use('/uploads/profile_images', express.static(uploadDirs.profile));
app.use('/uploads/course_images', express.static(uploadDirs.course));



// Upload Profile Image
app.post('/upload-profile-image', authenticateToken, upload.single('image'), (req, res) => {
    console.log('Headers:', req.headers);
    console.log('req.file:', req.file);
    console.log('req.body:', req.body);

    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }

    const userId = req.user.id;
    const filePath = '/uploads/profile_images/' + req.file.filename;

    const query = 'UPDATE users SET profile_image = ? WHERE id = ?';
    db.query(query, [filePath, userId], (err, result) => {
        if (err) return res.status(500).json({ message: 'Error uploading image', error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });

        const fullImageUrl = `${req.protocol}://${req.get('host')}${filePath}`;
        res.status(200).json({
            message: 'Profile image uploaded successfully',
            profileImageUrl: fullImageUrl,
        });
    });
});




// Image retrieval route
app.get('/get-profile-image/:id', authenticateToken, (req, res) => {
    const userId = req.params.id;

    // Query to get the profile image path from the database
    const query = 'SELECT profile_image FROM users WHERE id = ?';
    db.query(query, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching image', error: err.message });
        }

        if (result.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const imagePath = result[0].profile_image;

        if (!imagePath) {
            return res.status(404).json({ message: 'Profile image not found' });
        }
        const fullImageUrl = encodeURI(`${req.protocol}://${req.get('host')}${imagePath}`);
        res.status(200).json({
            message: 'Profile image fetched successfully',
            profileImageUrl: fullImageUrl, // Return the full URL to the frontend
        });
    });
});






app.post('/register', async (req, res) => {
    const { name, email, password, role = 'user' } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Name, email, and password are required' });
    }

    try {
        const checkUserSQL = 'SELECT * FROM Users WHERE email = ?';
        db.query(checkUserSQL, [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (results.length > 0) {
                return res.status(400).json({ message: 'Email already exists' });
            }

            try {
                const hashedPassword = await bcrypt.hash(password, 10);
                const insertUserSQL = 'INSERT INTO Users (name, email, password, role) VALUES (?, ?, ?, ?)';
                db.query(insertUserSQL, [name, email, hashedPassword, role], (err, result) => {
                    if (err) {
                        console.error('Database error during insertion:', err);
                        return res.status(500).json({ message: 'Database error during insertion' });
                    }
                    res.status(201).json({ message: 'User registered successfully' });
                });
            } catch (hashErr) {
                console.error('Error hashing password:', hashErr);
                res.status(500).json({ message: 'Error hashing password' });
            }
        });
    } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});



// 2. User Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM Users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
        if (err) return handleDbError(err, res);
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: '7d' });
        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });
    });
});

// 3. Update User Name
app.put('/update-user/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Only admins can update users' });

    const sql = 'UPDATE Users SET name = ? WHERE id = ?';
    db.query(sql, [name, id], (err, result) => {
        if (err) return handleDbError(err, res);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
        res.status(200).json({ message: 'User name updated successfully' });
    });
});

// 4. Change User Role
app.put('/change-role/:userId', authenticateToken, verifyAdmin, (req, res) => {
    const { userId } = req.params;
    const { role } = req.body;
    if (!['admin', 'non-admin'].includes(role)) return res.status(400).json({ message: 'Invalid role' });

    const sql = 'UPDATE Users SET role = ? WHERE id = ?';
    db.query(sql, [role, userId], (err, result) => {
        if (err) return handleDbError(err, res);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
        res.json({ message: 'Role updated successfully' });
    });
});

app.delete('/delete-user/:userId', authenticateToken, verifyAdmin, (req, res) => {
    const { userId } = req.params;

    // Check if the user exists
    const checkUserSql = 'SELECT * FROM Users WHERE id = ?';
    db.query(checkUserSql, [userId], (err, result) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete all related purchases for the user first
        const deletePurchasesSql = 'DELETE FROM purchases WHERE user_id = ?';
        db.query(deletePurchasesSql, [userId], (err) => {
            if (err) {
                console.error('Error deleting user purchases:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }

            // Now, delete the user
            const deleteUserSql = 'DELETE FROM Users WHERE id = ?';
            db.query(deleteUserSql, [userId], (err, result) => {
                if (err) {
                    console.error('Error deleting user:', err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }

                if (result.affectedRows === 0) {
                    return res.status(404).json({ error: 'User not found' });
                }

                res.status(200).json({ message: 'User deleted successfully' });
            });
        });
    });
});



  
  

// 6. Get All Users (Admin Only)
app.get('/users', authenticateToken, verifyAdmin, (req, res) => {
    const sql = 'SELECT id, name, email, role FROM Users';
    db.query(sql, (err, results) => {
        if (err) return handleDbError(err, res);
        res.json(results);
    });
});

// 7. Get Current User Details
app.get('/users/me', authenticateToken, (req, res) => {
    const sql = 'SELECT id, name, email, role FROM Users WHERE id = ?';
    db.query(sql, [req.user.id], (err, results) => {
        if (err) return handleDbError(err, res);
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });
        res.json(results[0]);
    });
});

// / Updated /users/me/courses Route
app.get('/users/me/courses', authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from token

    const sql = `
        SELECT 
            Courses.id AS course_id,
            Courses.title AS course_title,
            Users.name AS user_name
        FROM Courses 
        LEFT JOIN Users ON Courses.created_by = Users.id
        WHERE Courses.created_by = ? OR Courses.user_id = ?
    `;

    db.query(sql, [userId, userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database query failed' });
        res.status(200).json(results);
    });
});




// Input Validation Middleware
const validateInputs = (req, res, next) => {
    const { title, description, price } = req.body;
    if (!title || !description || typeof price !== 'number') {
        return res.status(400).json({ message: 'Invalid input data' });
    }
    next();
};

app.get('/user/courses', authenticateToken, async (req, res) => {
    console.log("User ID:", req.user.id); // Log to verify that the user ID is correctly passed
    const userId = req.user.id;

    db.query('SELECT * FROM courses WHERE user_id = ?', [userId], (err, courses) => {
        if (err) {
            console.error('Error fetching courses:', err);
            return res.status(500).send('Error fetching courses');
        }

        if (courses.length === 0) {
            return res.status(404).send('No courses found');
        }

        res.json({ courses });
    });
});


// Route to add a new course (example)
app.post('/user/courses', authenticateToken, (req, res) => {
    const { title, description } = req.body;
    const userId = req.user.id;

    if (!title || !description) {
        return res.status(400).send('Missing required fields');
    }

    // Query to insert a new course
    const query = 'INSERT INTO courses (title, description, user_id) VALUES (?, ?, ?)';
    db.query(query, [title, description, userId], (err, result) => {
        if (err) {
            console.error('Error adding course:', err);
            return res.status(500).send('Error adding course');
        }
        res.status(201).send('Course added successfully');
    });
});




// 8. Get All Courses (Public)
// app.get('/courses', (req, res) => {
//     const sql = 'SELECT id, title, description, price, duration FROM Courses';
//     db.query(sql, (err, results) => {
//         if (err) {
//             console.error('Database query error:', err);
//             return res.status(500).json({ message: 'Database query failed', error: err.message });
//         }
//         res.json(results);
//     });
// });
app.get('/courses', (req, res) => {
    const sql = 'SELECT id, title, description, price, duration, image_url FROM courses';

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).json({ message: 'Database query failed', error: err.message });
        }

        if (results.length === 0) {
            console.warn("No courses found in database.");
            return res.status(404).json({ message: "No courses available." });
        }

        // Append the server URL to the image path
        const updatedResults = results.map(course => ({
            ...course,
            image_url: `${req.protocol}://${req.get('host')}${course.image_url}`
        }));

        console.log("Courses fetched successfully:", updatedResults);
        res.json(updatedResults);
    });
});
// Updated Add a New Course Route with Validation
app.post('/courses', authenticateToken, upload.single('image'), (req, res) => {
    console.log("🔥 Incoming Request:");
    console.log("Headers:", req.headers);
    console.log("Body:", req.body);  // ✅ This should now contain form fields!
    console.log("File:", req.file);

    // Extract form data
    const { title, description, price, duration } = req.body;

    if (!title || !description || !price || !duration || !req.file) {
        console.error("⚠️ Missing fields. req.body:", req.body);
        return res.status(400).json({ message: 'All fields are required, including an image' });
    }

    const filePath = `/uploads/course_images/${req.file.filename}`;
    const addedBy = req.user.id;

    const sql = `INSERT INTO courses (title, description, price, duration, image_url, added_by, created_by) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;

    db.query(sql, [title, description, price, duration, filePath, addedBy, addedBy], (err, result) => {
        if (err) {
            return res.status(500).json({ message: 'Error creating course', error: err });
        }

        const fullImageUrl = `${req.protocol}://${req.get('host')}${filePath}`;
        res.status(201).json({
            message: "Course added successfully!",
            courseId: result.insertId,
            imageUrl: fullImageUrl
        });
    });
});

app.put('/courses/:id', upload.single('image'), (req, res) => {
    const courseId = req.params.id;
    const { title, description, price, duration } = req.body;
    const imageFile = req.file;

    console.log('Received:', req.body);
    console.log('Image file:', imageFile);

    // Query to check if course exists
    db.query('SELECT image_url FROM courses WHERE id = ?', [courseId], (err, rows) => {
        if (err) {
            console.error('🔥 Error:', err);
            return res.status(500).json({ message: 'Error checking course', error: err });
        }

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Course not found' });
        }

        let imageUrl = rows[0].image_url;

        // If an image is uploaded, handle the old image replacement
        if (imageFile) {
            const oldImagePath = path.join(__dirname, imageUrl);
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }
            imageUrl = `/uploads/course_images/${imageFile.filename}`;
        }

        // Update course details in the database
        db.query(
            'UPDATE courses SET title = ?, description = ?, price = ?, duration = ?, image_url = ? WHERE id = ?',
            [title, description, price, duration, imageUrl, courseId],
            (updateErr, updateResult) => {
                if (updateErr) {
                    console.error('🔥 Error updating course:', updateErr);
                    return res.status(500).json({ message: 'Error updating course', error: updateErr });
                }

                // Fetch and return the updated course
                db.query('SELECT * FROM courses WHERE id = ?', [courseId], (selectErr, updatedRows) => {
                    if (selectErr) {
                        console.error('🔥 Error fetching updated course:', selectErr);
                        return res.status(500).json({ message: 'Error fetching updated course', error: selectErr });
                    }

                    if (updatedRows.length === 0) {
                        return res.status(404).json({ message: 'Updated course not found' });
                    }

                    res.json(updatedRows[0]);
                });
            }
        );
    });
});



// app.post('/courses', authenticateToken, (req, res) => {
//     const { title, description, price, duration } = req.body;
//     const addedBy = req.user.id; // Get user ID from token

//     if (!title || !description || !price || !duration) {
//         return res.status(400).json({ message: 'All fields are required' });
//     }

//     const sql = `
//         INSERT INTO Courses (title, description, price, duration, added_by, created_by) 
//         VALUES (?, ?, ?, ?, ?, ?)
//     `;

//     db.query(sql, [title, description, price, duration, addedBy,], (err, result) => {
//         if (err) return handleDbError(err, res);
//         res.status(201).json({ message: "Course added successfully!", courseId: result.insertId });
//     });
// });


// Delete a course
app.delete('/courses/:id', (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM courses WHERE id = ?';

    db.query(query, [id], (err, result) => {
        if (err) {
            console.error('Error details:', err);
            return res.status(500).json({ message: 'Error deleting course', error: err });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Course not found' });
        }

        res.status(200).json({ message: 'Course deleted successfully' });
    });
});



app.post('/courses/buy/:courseId', authenticateToken, async (req, res) => {
    const { courseId } = req.params;
    const userId = req.user.id; // Extracted from the token
    const { startDate, emiPlan, emiAmount } = req.body; // Ensure emiPlan and emiAmount are passed from the client

    try {
        // Ensure the course exists
        const [course] = await db.promise().query('SELECT * FROM Courses WHERE id = ?', [courseId]);
        if (course.length === 0) {
            return res.status(404).json({ message: 'Course not found' });
        }

        // Log the retrieved course to inspect the `duration`
        console.log("Retrieved course:", course[0]);

        // Get the duration from the course (now assuming it is in months)
        const duration = course[0].duration;
        if (!duration) {
            return res.status(400).json({ message: 'Course does not have a valid duration' });
        }

        // Check if the user already bought the course
        const [purchase] = await db.promise().query(
            'SELECT * FROM Purchases WHERE user_id = ? AND course_id = ?',
            [userId, courseId]
        );
        if (purchase.length > 0) {
            return res.status(400).json({ message: 'Course already purchased' });
        }

        // Calculate purchase_date and expiry_date
        const currentDate = new Date();
        const calculatedStartDate = startDate ? new Date(startDate) : currentDate; // If no startDate passed, use current date

        // Calculate expiry date based on duration (assuming the duration is in months)
        const expiryDate = new Date(calculatedStartDate);
        expiryDate.setMonth(expiryDate.getMonth() + duration); // Add months

        // Format the dates for MySQL
        const purchaseDateFormatted = calculatedStartDate.toISOString().slice(0, 19).replace('T', ' ');
        const expiryDateFormatted = expiryDate.toISOString().slice(0, 19).replace('T', ' ');

        // Insert purchase record with EMI details
        await db.promise().query('INSERT INTO Purchases (user_id, course_id, start_date, expiry_date, duration, purchase_date, emi_installments, emi_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [
            userId,
            courseId,
            purchaseDateFormatted,
            expiryDateFormatted,
            duration,
            purchaseDateFormatted,
            emiPlan, // Number of installments
            emiAmount, // Installment amount
        ]);

        // Fetch user details for email
        const [user] = await db.promise().query('SELECT email, name FROM Users WHERE id = ?', [userId]);
        if (user.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Send email notification
        const transporter = nodemailer.createTransport({
            service: 'gmail', // Or your email service
            auth: {
                user: 'deepjadav4649@gmail.com',
                pass: 'rbsjfoldxfdnpkyv',
            },
            tls: {
                rejectUnauthorized: false, // Allow self-signed certificates
            },
        });

        const mailOptions = {
            from: 'deepjadav4649@gmail.com',
            to: user[0].email,
            subject: `Course Purchase Confirmation: ${course[0].title}`,
            html: `
                <html>
                    <body>
                        <h2>Dear ${user[0].name},</h2>
                        <p>Thank you for purchasing the course "<strong>${course[0].title}</strong>". You can start learning immediately!</p>
                        
                        <h3>Course Details</h3>
                        <table border="1" cellpadding="10" cellspacing="0">
                            <tr>
                                <th>Course Title</th>
                                <th>Price</th>
                                <th>Start Date</th>
                                <th>Duration</th>
                                <th>Expiry Date</th>
                            </tr>
                            <tr>
                                <td>${course[0].title}</td>
                                <td>₹${course[0].price}</td>
                                <td>${purchaseDateFormatted}</td>
                                <td>${duration} months</td>
                                <td>${expiryDateFormatted}</td>
                            </tr>
                        </table>

                        <p>Best regards,<br>Your Team</p>
                    </body>
                </html>
            `,
        };

        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully.');
        res.status(200).json({ message: 'Course purchased successfully and email sent.' });
    } catch (error) {
        console.error('Error during purchase:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});


// Route to fetch purchases for the logged-in user (GET)
app.get('/user/purchases', authenticateToken, async (req, res) => {
    const userId = req.user.id; // Extract user ID from the token

    try {
        // Fetch all purchases for the logged-in user
        const [purchases] = await db.promise().query(`
            SELECT p.id AS purchase_id, c.title AS course_title, p.start_date, p.expiry_date, p.emi_installments, p.emi_amount
            FROM Purchases p
            JOIN Courses c ON p.course_id = c.id
            WHERE p.user_id = ?`, [userId]);

        if (purchases.length === 0) {
            return res.status(404).json({ message: 'No courses purchased' });
        }

        // Send the purchases data
        res.status(200).json({ purchases });
    } catch (error) {
        console.error('Error fetching purchases:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Route to create a new purchase (POST)
app.post('/user/purchases', authenticateToken, async (req, res) => {
    const { course_id, start_date, expiry_date, emi_installments, emi_amount } = req.body; // Data from the request body
    const userId = req.user.id; // Extract user ID from the token

    if (!course_id || !start_date || !expiry_date || !emi_installments || !emi_amount) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // Insert the new purchase record into the database
        const result = await db.promise().query(`
            INSERT INTO Purchases (user_id, course_id, start_date, expiry_date, emi_installments, emi_amount)
            VALUES (?, ?, ?, ?, ?, ?)`,
            [userId, course_id, start_date, expiry_date, emi_installments, emi_amount]);

        // Send success response with the new purchase ID
        res.status(201).json({
            message: 'Purchase created successfully',
            purchase_id: result[0].insertId, // Return the inserted purchase ID
        });
    } catch (error) {
        console.error('Error creating purchase:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.get('/courses/purchased', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin';

    let sql = `
        SELECT c.*, p.created_at AS purchase_date, p.expiry_date AS expiry_date, 
               u.name AS user_name, u.email AS user_email
        FROM Courses c
        JOIN Purchases p ON c.id = p.course_id
        JOIN Users u ON p.user_id = u.id
    `;

    if (!isAdmin) {
        sql += ` WHERE c.created_by = ?`; // Filter courses added by non-admin user
    }

    console.log("UserId: ", userId);
    console.log("SQL Query: ", sql);

    db.query(sql, isAdmin ? [] : [userId], (err, results) => {
        if (err) {
            console.error('Database Error: ', err);
            return res.status(500).json({ message: 'Database error', error: err });
        }
        console.log("Query Results: ", results);
        res.json(results);
    });
});














// Check for expiring courses (run every 24 hours)
const checkForExpiringCourses = () => {
    const sql = 'SELECT * FROM Purchases WHERE course_expiry_date IS NOT NULL AND course_expiry_date <= NOW() + INTERVAL 7 DAY';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error checking expiring courses:', err);
            return;
        }
        results.forEach(purchase => {
            // Notify user about course expiry
            sendRenewalNotification(purchase); // Send email
        });
    });
};

// Send expiration notification to the user
const sendExpirationNotification = (userId, courseId) => {
    const sql = 'SELECT email FROM Users WHERE id = ?';
    db.query(sql, [userId], (err, userResults) => {
        if (err) return console.error('Error fetching user email:', err);
        const userEmail = userResults[0].email;
        // Send email notification (This can be done via an actual email service)
        console.log(`Sending expiration notification to ${userEmail} for course ${courseId}`);
    });
};

// Call checkForExpiringCourses periodically
setInterval(checkForExpiringCourses, 86400000); // Run every 24 hours



const checkUserPurchase = (userId, courseId) => {
    return new Promise((resolve, reject) => {
        const sql = 'SELECT * FROM Purchases WHERE user_id = ? AND course_id = ?';
        db.query(sql, [userId, courseId], (err, results) => {
            if (err) return reject(err);
            console.log('User purchase check:', results);  // Log the result
            resolve(results.length > 0);  // If there are any records, the user has purchased the course
        });
    });
};


const saveCoursePurchase = (userId, courseId) => {
    return new Promise((resolve, reject) => {
        const sql = 'INSERT INTO Purchases (user_id, course_id, purchase_date) VALUES (?, ?, NOW())';
        db.query(sql, [userId, courseId], (err, result) => {
            if (err) return reject(err);
            console.log('Purchase saved:', result);  // Log the result of the insert query
            resolve(result);
        });
    });
};


// Modified authenticateAdmin as a combination of authenticateToken and verifyAdmin
const authenticateAdmin = (req, res, next) => {
    authenticateToken(req, res, () => {
        verifyAdmin(req, res, next); // verifyAdmin checks the role is 'admin'
    });
};





// 5. Purchase a Course (User)
// Assuming authenticateToken middleware and db are already defined
// Function to calculate the expiry date based on purchase date and course duration
// const calculateExpiryDate = (purchaseDate, durationInWeeks) => {
//     const date = new Date(purchaseDate);
//     date.setDate(date.getDate() + durationInWeeks * 7); // Add duration in weeks
//     return date;
// };

// Calculate expiry date based on the duration and durationUnit
function calculateExpiryDate(startDate, duration, durationUnit) {
    let expiryDate = new Date(startDate);
    switch (durationUnit) {
        case 'days':
            expiryDate.setDate(expiryDate.getDate() + duration);
            break;
        case 'weeks':
            expiryDate.setDate(expiryDate.getDate() + duration * 7);
            break;
        case 'months':
            expiryDate.setMonth(expiryDate.getMonth() + duration);
            break;
        case 'years':
            expiryDate.setFullYear(expiryDate.getFullYear() + duration);
            break;
        default:
            return expiryDate;
    }
    return expiryDate;
}

// In your purchase creation route (POST /purchases)
app.post('/purchases', authenticateToken, (req, res) => {
    const { course_id, type, duration, durationUnit } = req.body;

    // Check if course_id is provided
    if (!course_id || !duration || !durationUnit) {
        return res.status(400).json({ message: 'Course ID, duration, and duration unit are required' });
    }

    const purchaseDate = new Date();
    const startDate = new Date(); // Current timestamp

    // Calculate expiry date using the utility function
    const expiryDate = calculateExpiryDate(startDate, duration, durationUnit);

    const sql = 'INSERT INTO Purchases (user_id, course_id, start_date, expiry_date, type, duration, durationUnit) VALUES (?, ?, ?, ?, ?, ?, ?)';

    db.query(sql, [req.user.id, course_id, purchaseDate, expiryDate, type, duration, durationUnit], (err, result) => {
        if (err) {
            console.error('Error in inserting purchase:', err);
            return res.status(500).json({ message: 'Error inserting data' });
        }
        res.status(201).json({ message: 'Course purchased successfully', purchaseId: result.insertId });
    });
});
// Assuming you're using some route to add a course to a user's purchases
app.post('/add-course', authenticateToken, async (req, res) => {
    const userId = req.user.id; // The user (admin or non-admin) adding the course
    const courseId = req.body.courseId; // The course ID to be added
    const startDate = new Date(); // Set the current date as the start date

    try {
        // Insert into Purchases table with added_by being the user who is adding the course
        const insertQuery = `
            INSERT INTO Purchases (user_id, course_id, added_by, start_date)
            VALUES (?, ?, ?, ?)
        `;

        const values = [userId, courseId, userId, startDate]; // All 4 values to match the columns

        await db.promise().query(insertQuery, values); // Execute the query with the provided values
        res.status(200).json({ message: 'Course added successfully.' });
    } catch (err) {
        console.error('Error adding course:', err);
        res.status(500).json({ message: 'Server error' });
    }
});








// Updated Role-Based Route Restriction for Purchases
app.get('/purchases', authenticateToken, (req, res) => {
    console.log('Authenticated user ID:', req.user.id); // Log user ID
    const sql = 'SELECT * FROM Purchases WHERE user_id = ?';
    db.query(sql, [req.user.id], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ message: 'Internal Server Error' });
        }
        console.log('Fetched purchases:', results);
        res.json(results);
    });
});




// app.get('/courses/purchased/:userId', (req, res) => {
//     const { userId } = req.params;
//     const query = `
//         SELECT 
//             c.*, 
//             p.expiry_date, 
//             DATE_ADD(p.purchase_date, INTERVAL p.duration * 7 DAY) AS calculated_expiry_date
//         FROM Courses c
//         JOIN Purchases p ON c.id = p.course_id
//         WHERE p.user_id = ?
//     `;
    
//     db.query(query, [userId], (err, results) => {
//         if (err) {
//             console.error('Error fetching courses:', err);
//             return res.status(500).json({ message: 'Error fetching courses' });
//         }
//         res.status(200).json(results);
//     });
// });
// Backend Route for Fetching Purchased Courses
app.get('/courses/purchased/:userId', (req, res) => {
    const { userId } = req.params;
    const query = `
      SELECT p.*, c.title, c.description, c.price
FROM Purchases p
JOIN Courses c ON p.course_id = c.id
WHERE p.user_id = ?
`;

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching courses:', err);
            return res.status(500).json({ message: 'Error fetching courses' });
        }

        // Send the data including durationUnit and price
        res.status(200).json(results);
    });
});

// 3. Get All Courses (Admin Only)
app.get('/admin/courses/purchased', authenticateToken, verifyAdmin, (req, res) => {
    const sql = `
        SELECT c.*, p.created_at AS purchase_date, p.expiry_date AS expiry_date, 
               u.name AS user_name, u.email AS user_email
        FROM Courses c
        JOIN Purchases p ON c.id = p.course_id
        JOIN Users u ON p.user_id = u.id
    `;
    
    db.query(sql, (err, results) => {
        if (err) return handleDbError(err, res);
        console.log('Courses fetched from DB:', results);
        res.json(results);
    });
});

// In the backend
app.get('/admin/courses1/purchased', authenticateToken, async (req, res) => {
    try {
        // Fetch courses with user details including the created_by name (admin/non-admin)
        const query = `
            SELECT 
                u.name AS user_name, 
                u.email AS user_email, 
                u.role AS user_role, 
                IFNULL(a.name, 'Unknown') AS created_by_name,  -- Show 'Unknown' if no created_by user is found
                COUNT(p.course_id) AS total_courses,
                SUM(c.price) AS total_price
            FROM Purchases p
            JOIN Users u ON p.user_id = u.id
            JOIN Courses c ON p.course_id = c.id
            LEFT JOIN Users a ON c.created_by = a.id  -- Fetch the name of the user who created the course
            GROUP BY u.id, a.name`; 

        const [results] = await db.promise().query(query);
        res.json(results);
    } catch (err) {
        console.error('Error fetching data:', err);
        res.status(500).json({ message: 'Server error' });
    }
});


app.get('/non-admin/courses/purchased', authenticateToken, async (req, res) => {
    const { userId, role } = req.user; // Extract user ID and role from token
    if (role !== 'non-admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    try {
        const courses = await db.query(
            `SELECT c.*, u.name as buyer_name 
             FROM courses c 
             JOIN users u ON c.purchased_by = u.id 
             WHERE c.created_by = ?`, [userId]
        );
        res.json(courses);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching data' });
    }
});






app.post('/admin/send-renewal-notification', authenticateAdmin, (req, res) => {
    console.log('Request received for sending renewal notification');
        const { userId, courseName, message } = req.body;

    try {
        if (!userId || !message) {
            return res.status(400).send({ message: 'Missing userId or message.' });
        }

        // Retrieve the user email
        const sql = 'SELECT email FROM Users WHERE id = ?';
        db.query(sql, [userId], (err, results) => {
            if (err) {
                console.error('Error fetching user email:', err);
                return res.status(500).send({ message: 'Error fetching user email' });
            }
            if (results.length === 0) {
                return res.status(404).send({ message: 'User not found' });
            }

            const userEmail = results[0].email;
            console.log('User email:', userEmail);  // Log the email

            // Send the renewal notification email
            sendRenewalNotification({ email: userEmail, title: 'Course Title', end_date: '2025-01-31' });

            res.status(200).send({ message: 'Notification sent successfully' });
        });
    } catch (error) {
        console.error('Error sending notification:', error);
        res.status(500).send({ message: 'An error occurred while sending the notification.' });
    }
});





// Query to get users whose memberships are expiring in 5 days
app.get('/api/check-renewal', (req, res) => {
    const query = `
        SELECT u.id, u.email, c.title, p.end_date
        FROM Users u
        JOIN Purchases p ON u.id = p.user_id
        JOIN Courses c ON p.course_id = c.id
        WHERE p.end_date IS NOT NULL AND DATEDIFF(p.end_date, NOW()) <= 5;
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching data' });
        }

        if (results.length > 0) {
            // Send renewal notifications to users
            results.forEach(result => {
                sendRenewalNotification(result);
            });
            return res.status(200).json({ message: 'You have courses nearing expiration!', courses: results });
        } else {
            return res.status(200).json({ message: 'No courses are expiring soon.' });
        }
    });
});


// Mock user data (in a real app, this data would come from a database)
const notifications = [
    {
        _id: '1',
        courseName: 'React for Beginners',
        message: 'Your course is about to expire.',
        expiryDate: new Date(new Date().setDate(new Date().getDate() + 5)),  // Expiry in 5 days
    },
    {
        _id: '2',
        courseName: 'Advanced JavaScript',
        message: 'Your course is now active.',
        expiryDate: new Date(new Date().setDate(new Date().getDate() + 15)),  // Expiry in 15 days
    },
];


function isAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ message: 'Admin access required' });
}


// Route to handle course renewal
// app.post('/courses/renew/:courseId', authenticateToken, async (req, res) => {
//     const { courseId } = req.params;
//     const userId = req.user.id; // Extracted from the token
//     const { durationInMonths } = req.body; // Duration passed for renewal

//     console.log('Course ID:', courseId);
//     console.log('User ID:', userId);
//     console.log('Duration In Months:', durationInMonths);

//     try {
//         // Fetch the purchase record
//         const [purchase] = await db.promise().query('SELECT * FROM Purchases WHERE user_id = ? AND course_id = ?', [
//             userId, courseId
//         ]);

//         console.log('Purchase:', purchase); // Log the purchase data

//         if (purchase.length === 0) {
//             return res.status(404).json({ message: 'Course not found for this user.' });
//         }

//         // Calculate new expiry date
//         const currentExpiryDate = new Date(purchase[0].expiry_date);
//         const newExpiryDate = new Date(currentExpiryDate);
//         newExpiryDate.setDate(newExpiryDate.getDate() + durationInMonths * 30); // Add duration in months

//         // Format the expiry date to match MySQL DATETIME format (YYYY-MM-DD HH:MM:SS)
//         const mysqlFormattedDate = newExpiryDate.toISOString().slice(0, 19).replace('T', ' ');
//         const mysqlFormattedPurchaseDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

//         console.log('Formatted Date:', mysqlFormattedDate, mysqlFormattedPurchaseDate); // Log the formatted date

//         await db.promise().query(
//             'UPDATE Purchases SET purchase_date = ?, expiry_date = ?, status = ? WHERE id = ?',
//             [mysqlFormattedPurchaseDate, mysqlFormattedDate, 'Active', purchase[0].id]
//         );

//         // Fetch the course details for the email
//         const [course] = await db.promise().query('SELECT * FROM Courses WHERE id = ?', [courseId]);
//         if (course.length === 0) {
//             return res.status(404).json({ message: 'Course not found' });
//         }

//         console.log('Course details:', course[0]); // Log the course data for email

//         // Fetch user details for the email
//         const [user] = await db.promise().query('SELECT email, name FROM Users WHERE id = ?', [userId]);
//         if (user.length === 0) {
//             return res.status(404).json({ message: 'User not found' });
//         }

//         // Send email notification for renewal
//         const transporter = nodemailer.createTransport({
//             service: 'gmail', // Or your email service
//             auth: {
//                 user: 'deepjadav4649@gmail.com',
//                 pass: 'rbsjfoldxfdnpkyv', // Ensure this is a secure method for password storage
//             },
//             tls: {
//                 rejectUnauthorized: false, // Allow self-signed certificates
//             },
//         });

//         const mailOptions = {
//             from: 'deepjadav4649@gmail.com',
//             to: user[0].email,
//             subject: `Course Renewal Confirmation: ${course[0].title}`,
//             html: `
//                 <html>
//                     <body>
//                         <h2>Dear ${user[0].name},</h2>
//                         <p>Your course "<strong>${course[0].title}</strong>" has been successfully renewed.</p>
                        
//                         <h3>Course Details</h3>
//                         <table border="1" cellpadding="10" cellspacing="0">
//                             <tr>
//                                 <th>Course Title</th>
//                                 <th>Price</th>
//                                 <th>Duration</th>
//                                 <th>New Expiry Date</th>
//                             </tr>
//                             <tr>
//                                 <td>${course[0].title}</td>
//                                 <td>${course[0].price}</td>
//                                 <td>${course[0].duration} weeks</td>
//                                 <td>${newExpiryDate.toLocaleDateString()}</td>
//                             </tr>
//                         </table>
                        
//                         <p>Best regards,<br>Your Team</p>
//                     </body>
//                 </html>
//             `,
//         };

//         await transporter.sendMail(mailOptions);
//         console.log('Email sent successfully.');

//         // Respond with the updated dates and message
//         res.status(200).json({
//             message: 'Course renewed successfully and email sent.',
//             newExpiryDate: newExpiryDate.toISOString(), // Send the updated expiry date
//             newPurchaseDate: mysqlFormattedPurchaseDate, // Send the updated purchase date
//         });

//     } catch (error) {
//         console.error('Error renewing course:', error);
//         res.status(500).json({ message: 'Server error', error: error.message });
//     }
// });

// Backend Route for Renewing a Course
// app.post('/courses/renew/:courseId', authenticateToken, async (req, res) => {
//     const { courseId } = req.params;
//     const userId = req.user.id; // Extracted from the token
//     const { duration } = req.body; // Duration and its unit passed for renewal

//     console.log('Course ID:', courseId);
//     console.log('User ID:', userId);
//     console.log('Duration:', duration);

//     try {
//         // Fetch the purchase record
//         const [purchase] = await db.promise().query('SELECT * FROM Purchases WHERE user_id = ? AND course_id = ?', [
//             userId, courseId
//         ]);

//         if (purchase.length === 0) {
//             return res.status(404).json({ message: 'Course not found for this user.' });
//         }

//         const currentDate = new Date(); // Current date
//         let newExpiryDate = new Date(currentDate); // Start from current date

//         // Calculate expiry date based on duration and unit
//         switch (durationUnit.toLowerCase()) {
//             case 'days':
//                 newExpiryDate.setDate(newExpiryDate.getDate() + parseInt(duration)); // Add duration in days
//                 break;
//             case 'weeks':
//                 newExpiryDate.setDate(newExpiryDate.getDate() + parseInt(duration) * 7); // Add duration in weeks (7 days per week)
//                 break;
//             case 'months':
//                 newExpiryDate.setMonth(newExpiryDate.getMonth() + parseInt(duration)); // Add duration in months
//                 break;
//             case 'years':
//                 newExpiryDate.setFullYear(newExpiryDate.getFullYear() + parseInt(duration)); // Add duration in years
//                 break;
//             default:
//                 return res.status(400).json({ message: 'Invalid duration unit' });
//         }

//         // Format expiry and purchase dates for MySQL
//         const mysqlFormattedExpiryDate = newExpiryDate.toISOString().slice(0, 19).replace('T', ' ');
//         const mysqlFormattedPurchaseDate = currentDate.toISOString().slice(0, 19).replace('T', ' ');

//         console.log('Formatted Expiry Date:', mysqlFormattedExpiryDate);
//         console.log('Formatted Purchase Date:', mysqlFormattedPurchaseDate);

//         // Update the purchase record in the database
//         await db.promise().query(
//             'UPDATE Purchases SET purchase_date = ?, expiry_date = ?, status = ? WHERE id = ?',
//             [mysqlFormattedPurchaseDate, mysqlFormattedExpiryDate, 'Active', purchase[0].id]
//         );

//         // Fetch the course details for the email
//         const [course] = await db.promise().query('SELECT * FROM Courses WHERE id = ?', [courseId]);
//         if (course.length === 0) {
//             return res.status(404).json({ message: 'Course not found' });
//         }

//         // Fetch user details for the email
//         const [user] = await db.promise().query('SELECT email, name FROM Users WHERE id = ?', [userId]);
//         if (user.length === 0) {
//             return res.status(404).json({ message: 'User not found' });
//         }

//         // Send email notification for renewal
//         const transporter = nodemailer.createTransport({
//             service: 'gmail',
//             auth: {
//                 user: 'deepjadav4649@gmail.com',
//                 pass: 'rbsjfoldxfdnpkyv', // Secure this for production use
//             },
//             tls: {
//                 rejectUnauthorized: false,
//             },
//         });

//const mailOptions = {
//             from: 'deepjadav4649@gmail.com',
//             to: user[0].email,
//             subject: `Course Renewal Confirmation: ${course[0].title}`,
//             html: `
//                 <html>
//                     <body>
//                         <h2>Dear ${user[0].name},</h2>
//                         <p>Your course "<strong>${course[0].title}</strong>" has been successfully renewed.</p>
                        
//                         <h3>Course Details</h3>
//                         <table border="1" cellpadding="10" cellspacing="0">
//                             <tr>
//                                 <th>Course Title</th>
//                                 <th>Price</th>
//                                 <th>Duration</th>
//                                 <th>New Expiry Date</th>
//                             </tr>
//                             <tr>
//                                 <td>${course[0].title}</td>
//                                 <td>₹${course[0].price}</td>
//                                 <td>${duration} ${durationUnit}</td>
//                                 <td>${newExpiryDate.toLocaleDateString()}</td>
//                             </tr>
//                         </table>
                        
//                         <p>Best regards,<br>Your Team</p>
//                     </body>
//                 </html>
//             `,
//         };

//         await transporter.sendMail(mailOptions);
//         console.log('Email sent successfully.');

//         // Respond with the updated dates
//         res.status(200).json({
//             messag         e: 'Course renewed successfully and email sent.',
//             newExpiryDate: mysqlFormattedExpiryDate,
//             newPurchaseDate: mysqlFormattedPurchaseDate,
//         });
//     } catch (error) {
//         console.error('Error renewing course:', error);
//         res.status(500).json({ message: 'Server error', error: error.message });
//     }
// });

app.post('/send-expiry-notification', authenticateToken, async (req, res) => {
    const { courseId } = req.body; // Course ID to check expiry
    const userId = req.user.id; // Extracted from the token

    try {
        // Fetch the purchase record to get course expiry date
        const [purchase] = await db.promise().query('SELECT * FROM Purchases WHERE user_id = ? AND course_id = ?', [userId, courseId]);

        if (purchase.length === 0) {
            return res.status(404).json({ message: 'Course not found for this user.' });
        }

        // Get course expiry date and check if it's nearing expiry
        const expiryDate = new Date(purchase[0].expiry_date);
        const currentDate = new Date();
        const diffTime = expiryDate - currentDate; // Time difference in milliseconds

        // If the course is expiring in less than 7 days, send a notification
        if (diffTime <= 7 * 24 * 60 * 60 * 1000) {  // 7 days in milliseconds
            // Fetch course details
            const [course] = await db.promise().query('SELECT * FROM Courses WHERE id = ?', [courseId]);
            if (course.length === 0) {
                return res.status(404).json({ message: 'Course not found' });
            }

            // Fetch user details for the email
            const [user] = await db.promise().query('SELECT email, name FROM Users WHERE id = ?', [userId]);
            if (user.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Send email notification for renewal
            const transporter = nodemailer.createTransport({
                service: 'gmail', // Or your email service
                auth: {
                    user: 'deepjadav4649@gmail.com',
                    pass: 'rbsjfoldxfdnpkyv', // Ensure this is a secure method for password storage
                },
                tls: {
                    rejectUnauthorized: false, // Allow self-signed certificates
                },
            });

            // Send expiry notification email
            const mailOptions = {
                from: 'deepjadav4649@gmail.com',
                to: user[0].email,
                subject: `Course Expiry Alert: ${course[0].title}`,
                html: `
                    <html>
                    <body>
                        <h2>Dear ${user[0].name},</h2>
                        <p>We want to notify you that your course "<strong>${title}</strong>" is expiring soon.</p>
                         <p><strong>Expiry Date:</strong> ${formattedExpiryDate}</p>
                            <p>Please renew your course soon to continue enjoying the benefits.</p>
                        
                        <h3>Course Details</h3>
                        <table border="1" cellpadding="10" cellspacing="0">
                            <tr>
                                <th>Course Title</th>
                                <th>Price</th>
                                <th>Duration</th>
                                <th>New Expiry Date</th>
                            </tr>
                            <tr>
                                <td>${course[0].title}</td>
                                <td>${course[0].price}</td>
                                <td>${course[0].duration} weeks</td>
                                <td>${newExpiryDate.toLocaleDateString()}</td>
                            </tr>
                        </table>
                        
                        <p>Best regards,<br>Your Team</p>
                    </body>
                </html>
                `,
            };

            await transporter.sendMail(mailOptions);
            console.log('Expiry notification email sent successfully.');

            // Respond with success
            res.status(200).json({ message: 'Expiry notification email sent successfully.' });
        } else {
            res.status(200).json({ message: 'Course is not nearing expiry.' });
        }
    } catch (error) {
        console.error('Error sending expiry notification:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});


// // Schedule cron job to run daily at 8:00 AM
// cron.schedule('14 15 * * *', async () => {
//     console.log('Running cron job to check for expiring courses.');

//     try {
//         const query = `
//     SELECT p.*, u.email, u.name, c.title, c.price, c.duration
//     FROM Purchases p
//     INNER JOIN Users u ON p.user_id = u.id
//     INNER JOIN Courses c ON p.course_id = c.id
//     WHERE DATEDIFF(p.expiry_date, CURDATE()) BETWEEN 1 AND 7 
//     AND p.renewed = FALSE
//     AND (p.last_notification_date IS NULL OR p.last_notification_date <= CURDATE());
// `;

//         const [results] = await db.promise().query(query);

//         if (results.length === 0) {
//             console.log('No expiring courses found.');
//             return;
//         }

//         for (const record of results) {
//             const { email, name, title, expiry_date, user_id, course_id, price, duration } = record;
//             const daysRemaining = Math.max(0, Math.ceil((new Date(expiry_date) - new Date()) / (1000 * 3600 * 24))); // Calculate days remaining
//             const formattedExpiryDate = new Date(expiry_date).toLocaleDateString();

//             const mailOptions = {
//                 from: 'deepjadav4649@gmail.com',
//                 to: email,
//                 subject: `Reminder: Your course "${title}" is expiring soon!`,
//                 html: `
//                     <html>
//                     <body>
//                         <h2>Dear ${name},</h2>
//                         <p>We want to notify you that your course "<strong>${title}</strong>" is expiring in <strong>${daysRemaining} days</strong>.</p>
//                         <p><strong>Expiry Date:</strong> ${formattedExpiryDate}</p>
//                         <p>Please renew your course soon to continue enjoying the benefits.</p>
                        
//                         <h3>Course Details</h3>
//                         <table border="1" cellpadding="10" cellspacing="0">
//                             <tr>
//                                 <th>Course Title</th>
//                                 <th>Price</th>
//                                 <th>Duration</th>
//                                 <th>New Expiry Date</th>
//                             </tr>
//                             <tr>
//                                 <td>${title}</td>
//                                 <td>${price}</td>
//                                 <td>${duration} weeks</td>
//                                 <td>${formattedExpiryDate}</td>
//                             </tr>
//                         </table>
                        
//                         <p>Best regards,<br>Your Team</p>
//                     </body>
//                     </html>
//                 `,
//             };

//             try {
//                 await transporter.sendMail(mailOptions);
//                 console.log(`Expiry notification email sent to ${email}.`);

//                 // Update the last notification date
//                 await db.promise().query(
//                     'UPDATE Purchases SET last_notification_date = CURDATE() WHERE user_id = ? AND course_id = ?',
//                     [user_id, course_id]
//                 );
//             } catch (error) {
//                 console.error(`Failed to send email to ${email}:`, error.message);
//             }
//         }
//     } catch (error) {
//         console.error('Error running cron job:', error.message);
//     }
// });

// // Function to check expiring courses and send notifications
// const checkExpiringCourses = async () => {
//     console.log('Running job to check for expiring courses.');

//     try {
//         const query = `
//     SELECT p.*, u.email, u.name, c.title, c.price, c.duration
//     FROM Purchases p
//     INNER JOIN Users u ON p.user_id = u.id
//     INNER JOIN Courses c ON p.course_id = c.id
//     WHERE DATEDIFF(p.expiry_date, CURDATE()) BETWEEN 1 AND 7 
//     AND p.renewed = FALSE
//     AND (p.last_notification_date IS NULL OR p.last_notification_date <= CURDATE());
// `;

//         const [results] = await db.promise().query(query);

//         if (results.length === 0) {
//             console.log('No expiring courses found.');
//             return;
//         }

//         for (const record of results) {
//             const { email, name, title, expiry_date, user_id, course_id, price, duration } = record;
//             const daysRemaining = Math.max(0, Math.ceil((new Date(expiry_date) - new Date()) / (1000 * 3600 * 24))); // Calculate days remaining
//             const formattedExpiryDate = new Date(expiry_date).toLocaleDateString();

//             const mailOptions = {
//                 from: 'deepjadav4649@gmail.com',
//                 to: email,
//                 subject: `Reminder: Your course "${title}" is expiring soon!`,
//                 html: `
//                     <html>
//                     <body>
//                         <h2>Dear ${name},</h2>
//                         <p>We want to notify you that your course "<strong>${title}</strong>" is expiring in <strong>${daysRemaining} days</strong>.</p>
//                         <p><strong>Expiry Date:</strong> ${formattedExpiryDate}</p>
//                         <p>Please renew your course soon to continue enjoying the benefits.</p>
                        
//                         <h3>Course Details</h3>
//                         <table border="1" cellpadding="10" cellspacing="0">
//                             <tr>
//                                 <th>Course Title</th>
//                                 <th>Price</th>
//                                 <th>Duration</th>
//                                 <th>New Expiry Date</th>
//                             </tr>
//                             <tr>
//                                 <td>${title}</td>
//                                 <td>${price}</td>
//                                 <td>${duration} weeks</td>
//                                 <td>${formattedExpiryDate}</td>
//                             </tr>
//                         </table>
                        
//                         <p>Best regards,<br>Your Team</p>
//                     </body>
//                     </html>
//                 `,
//             };

//             try {
//                 await transporter.sendMail(mailOptions);
//                 console.log(`Expiry notification email sent to ${email}.`);

//                 // Update the last notification date
//                 await db.promise().query(
//                     'UPDATE Purchases SET last_notification_date = CURDATE() WHERE user_id = ? AND course_id = ?',
//                     [user_id, course_id]
//                 );
//                 console.log(`Updated last_notification_date for user_id=${user_id}, course_id=${course_id}.`);
//             } catch (error) {
//                 console.error(`Failed to send email to ${email}:`, error.message);
//             }
//         }
//     } catch (error) {
//         console.error('Error running job:', error.message);
//     }
// };

// // Schedule the job to run every 10 seconds
// setInterval(checkExpiringCourses, 86400000); // Interval in milliseconds (86,400,000ms = 1 day)

// Schedule cron job to run daily at 8:00 AM
cron.schedule('03 11 * * *', async () => {
    console.log('Running daily cron job to check for expiring courses.');
    await checkExpiringCourses('days'); // Indicate the unit of time as 'days'
}, {
    timezone: "Asia/Kolkata", // Adjust to your local timezone
});

// Function to check expiring courses and send notifications
const checkExpiringCourses = async (unit) => {
    try {
        const query = `
            SELECT p.*, u.email, u.name, c.title, c.price, c.duration
            FROM Purchases p
            INNER JOIN Users u ON p.user_id = u.id
            INNER JOIN Courses c ON p.course_id = c.id
            WHERE DATEDIFF(p.expiry_date, CURDATE()) BETWEEN 0 AND 7 
            AND p.renewed = FALSE
            AND (p.last_notification_date IS NULL OR p.last_notification_date < CURDATE());
        `;
        const [results] = await db.promise().query(query);

        if (results.length === 0) {
            console.log('No expiring courses found.');
            return;
        }

        for (const record of results) {
            const { email, name, title, expiry_date, user_id, course_id, price, duration } = record;
            const expiryDateTime = new Date(expiry_date);
            const now = new Date();

            // Calculate time remaining
            let timeRemaining;
            let formattedTimeRemaining;

            if (unit === 'days') {
                timeRemaining = Math.max(0, Math.ceil((expiryDateTime - now) / (1000 * 3600 * 24)));
                formattedTimeRemaining = `${timeRemaining} day(s)`;
            }

            const formattedExpiryDate = expiryDateTime.toLocaleDateString();

            const mailOptions = {
                from: 'deepjadav4649@gmail.com', // Replace with your email
                to: email,
                subject: `Reminder: Your course "${title}" is expiring soon!`,
                html: `
                    <html>
                    <body>
                        <h2>Dear ${name},</h2>
                        <p>We want to notify you that your course "<strong>${title}</strong>" is expiring in <strong>${formattedTimeRemaining}</strong>.</p>
                        <p><strong>Expiry Date:</strong> ${formattedExpiryDate}</p>
                        <p>Please renew your course soon to continue enjoying the benefits.</p>
                        
                        <h3>Course Details</h3>
                        <table border="1" cellpadding="10" cellspacing="0">
                            <tr>
                                <th>Course Title</th>
                                <th>Price</th>
                                <th>Duration</th>
                                <th>New Expiry Date</th>
                            </tr>
                            <tr>
                                <td>${title}</td>
                                <td>${price}</td>
                                <td>${duration} weeks</td>
                                <td>${formattedExpiryDate}</td>
                            </tr>
                        </table>
                        
                        <p>Best regards,<br>Your Team</p>
                    </body>
                    </html>
                `,
            };

            try {
                await transporter.sendMail(mailOptions);
                console.log(`Expiry notification email sent to ${email}.`);

                // Update the last notification date
                await db.promise().query(
                    'UPDATE Purchases SET last_notification_date = CURDATE() WHERE user_id = ? AND course_id = ?',
                    [user_id, course_id]
                );
                console.log(`Updated last_notification_date for user_id=${user_id}, course_id=${course_id}.`);
            } catch (error) {
                console.error(`Failed to send email to ${email}:`, error.message);
            }
        }
    } catch (error) {
        console.error('Error running job:', error.message);
    }
};





// Endpoint to get expiring courses
app.get('/expiring-courses', (req, res) => {
    const query = `
        SELECT c.id, c.title, u.name AS user_name, c.expiry_date, c.notification_sent
        FROM courses c
        JOIN users u ON c.user_id = u.id
        WHERE c.expiry_date <= NOW() AND c.notification_sent = 0;
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error executing query:', err);
            return res.status(500).send('Server error');
        }

        // Calculate the time remaining for each course
        const expiringCourses = results.map((course) => {
            const expiryDate = new Date(course.expiry_date);
            const timeRemaining = Math.floor((expiryDate - new Date()) / (1000 * 60 * 60 * 24)); // in days
            return {
                ...course,
                time_remaining: timeRemaining < 0 ? 'Expired' : `${timeRemaining} days`,
            };
        });

        res.json(expiringCourses);
    });
});

// Endpoint to send notifications and update courses
app.post('/send-notifications', (req, res) => {
    const query = `
        UPDATE courses
        SET notification_sent = 1
        WHERE expiry_date <= NOW() AND notification_sent = 0;
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error executing query:', err);
            return res.status(500).send('Server error');
        }

        // Optionally send actual email/notification logic here.
        res.send({ message: 'Notifications sent successfully' });
    });
});

// Endpoint to fetch courses for a user
app.get('/api/user/courses', (req, res) => {
    const userId = 1; // Replace with dynamic user ID from authentication

    const query = `
        SELECT c.id, c.title, c.price, c.expiry_date,
               DATEDIFF(c.expiry_date, NOW()) AS time_remaining
        FROM courses c
        WHERE c.user_id = ?
    `;

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching courses:', err);
            return res.status(500).json({ message: 'Error fetching courses' });
        }

        // Format the results to include time remaining in a user-friendly way
        const formattedCourses = results.map((course) => ({
            ...course,
            time_remaining: course.time_remaining < 0 ? 'Expired' : `${course.time_remaining} days`
        }));

        res.json(formattedCourses);
    });
});

app.post('/payments', authenticateToken, async (req, res) => {
    const { userId, courseId, paymentAmount, createdBy } = req.body;

    try {
        const result = await db.query(
            'INSERT INTO Payments (user_id, course_id, payment_amount, created_by) VALUES (?, ?, ?, ?)',
            [userId, courseId, paymentAmount, createdBy]
        );
        res.status(201).json({ message: 'Payment successful', paymentId: result.insertId });
    } catch (error) {
        console.error('Error recording payment:', error);
        res.status(500).json({ message: 'Payment failed' });
    }
});
// Fetch all payments (or payments for a specific user)
app.get('/payments', authenticateToken, (req, res) => {
    try {
        const { userId } = req.query; // Optional filter by userId
        console.log('Fetching payments for userId:', userId);

        let query = 'SELECT * FROM Payments';
        let queryParams = [];

        if (userId) {
            query += ' WHERE user_id = ?';
            queryParams.push(userId);
        }

        console.log('Running query:', query);  // Log the query and parameters being used

        // Execute the query with a callback
        db.query(query, queryParams, (error, results) => {
            if (error) {
                console.error('Error fetching payments:', error);
                return res.status(500).json({ message: 'Failed to fetch payments' });
            }

            console.log('Payments fetched:', results);  // Log the results from the query
            res.status(200).json(results);
        });

    } catch (error) {
        console.error('Error fetching payments:', error);
        res.status(500).json({ message: 'Failed to fetch payments' });
    }
});

app.put('/users/update-mobile', authenticateToken, async (req, res) => {
    const { mobile_number } = req.body;
    const userId = req.user.id;  // Get user ID from decoded token

    if (!mobile_number) {
        return res.status(400).json({ message: 'Mobile number is required' });
    }

    try {
        const result = await db.query(
            'UPDATE users SET mobile_number = ? WHERE id = ?',
            [mobile_number, userId]
        );
        res.status(200).json({ message: 'Mobile number updated successfully' });
    } catch (error) {
        console.error('Error updating mobile number:', error);
        res.status(500).json({ message: 'Failed to update mobile number' });
    }
});


// Start server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});


