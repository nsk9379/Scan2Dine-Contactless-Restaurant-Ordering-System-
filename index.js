import express from "express"
import bodyParser from "body-parser"
import pg from "pg"

import nodemailer from "nodemailer"       //email otp
import twilio from 'twilio';              //phone otp
import crypto from "crypto"
import bcrypt from 'bcrypt';              //Password Security
import session from "express-session"     //
import dotenv from "dotenv";              //connecting .env file

import path from "path";
import fs from "fs";

import QRCode from "qrcode"

import multer from "multer";
import streamifier from "streamifier";
import { v2 as cloudinary } from 'cloudinary';

// Multer memory storage
const storage = multer.memoryStorage();
const upload = multer({ storage: multer.memoryStorage() }); // store file in memory only
// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});


// import Razorpay from "razorpay";

// const razorpay = new Razorpay({
//   key_id: process.env.RAZORPAY_KEY_ID,    // from Razorpay Dashboard
//   key_secret: process.env.RAZORPAY_KEY_SECRET
// });


import { v4 as uuidv4, validate as uuidValidate } from "uuid"
//to generate new UUID if session_id on customer side was string or it was not generated


dotenv.config();

const port=process.env.PORT|| 3000;
const app=express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//File upload (multer middleware)
// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     const dir = './public/imageUploads';
//     if (!fs.existsSync(dir)) {
//       fs.mkdirSync(dir, { recursive: true });
//     }
//     cb(null, dir);
//   },
//   filename: function (req, file, cb) {
//     const uniqueName = Date.now() + '-' + file.originalname.replace(/\s+/g, '');
//     cb(null, uniqueName);
//   }
// });
// const upload = multer({ storage });


const { Client } = pg;
const db = new Client({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
});
db.connect()
  .then(() => console.log("✅ Connected to PostgreSQL database."))
  .catch((err) => console.error("❌ Failed to connect to PostgreSQL:", err));



app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production'
  }
}));





function ensureLoggedIn(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.redirect("/login");
  }
  next();
}


app.get("/",(req,res)=>{
    res.render("hotel/1_welcome.ejs");
})
app.get("/about",(req,res)=>{
    res.render("hotel/2_about.ejs");
})
app.get("/register",(req,res)=>{
    res.render("hotel/3_registerContact.ejs");
})
app.get("/login",(req,res)=>{
    res.render("hotel/5_login.ejs");
})
app.post("/setpass",(req,res)=>{         //R
    res.render("hotel/4_setPassAfterRegister.ejs");
})
app.post("/home",(req,res)=>{        
    res.render("hotel/6_homeOrDashboard.ejs",{hotelName:"Great"});
})
app.get("/input-status",(req,res)=>{
    res.render("hotel/22_inputstatus.ejs");
})

//Register
//Email and phone otp/password send/verification  
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});
function sendEmailOTP(email, otp) {
  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: email,
    subject: 'Scan2Dine – OTP Verification',
    text: `Your OTP for registration is: ${otp}`
  };
  return transporter.sendMail(mailOptions);
}
app.post('/register/send-otp', async (req, res) => {
  const { contact } = req.body;
  const otp = generateOTP();

  try {
    // Check if user already exists (email or phone)
    const result = await db.query(
      'SELECT * FROM users WHERE contact=$1',
      [contact]
    );

    if (result.rows.length > 0) {
      // User already registered, redirect to login
      return res.render('hotel/5_login.ejs', {
        message: 'User already registered. Please log in.',
      });
    }

    // Store OTP and contact in session
    req.session.otp = otp;
    req.session.contact = contact;

    // Send OTP via Email or SMS
    if (contact.includes('@')) {
      await sendEmailOTP(contact, otp);
      res.render('hotel/3_verifyContact.ejs', {
        contact,
        message: 'OTP sent to your email.',
      });
    } else {
      await sendSMSOTP(contact, otp);
      res.render('hotel/3_verifyContact.ejs', {
        contact,
        message: 'OTP sent to your phone.',
      });
    }

  } catch (err) {
    console.error('OTP sending failed:', err);
    res.render('hotel/3_registerContact.ejs', {
      message: 'Error sending OTP. Try again.',
    });
  }
});
app.post('/register/verify-otp', (req, res) => {
  const { contact, otp } = req.body;

  // Match OTP and contact with session data
  if (req.session.otp === otp && req.session.contact === contact) {
    // OTP matched, clear session OTP and keep contact
    req.session.otp = null;
    req.session.contact = contact;
    res.redirect('/register/set-password');
  } else {
    // OTP doesn't match
    res.render("hotel/3_verifyContact.ejs", {
      message: 'Invalid OTP. Please try again.',
      contact
    });
  }
});

app.get('/register/set-password', (req, res) => {
  if (!req.session.contact) return res.redirect('/register');
  res.render('hotel/4_setPassAfterRegister.ejs', { contact: req.session.contact });
});
app.post('/register/set-password', async (req, res) => {
  const { password, confirmPassword } = req.body;

  // Try to get contact from either registration or forgot-password flow
  const contact = req.session.contact || req.session.resetContact;

  if (!contact) return res.redirect('/register');  // fallback

  if (password !== confirmPassword) {
    return res.render('hotel/4_setPassAfterRegister.ejs', {
      contact,
      message: 'Passwords do not match.'
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if user already exists
    const result = await db.query('SELECT * FROM users WHERE contact = $1', [contact]);

    if (result.rows.length > 0) {
      // User exists → Update password
      await db.query('UPDATE users SET password = $1 WHERE contact = $2', [hashedPassword, contact]);
    } else {
      // New user → Insert
      await db.query('INSERT INTO users (contact, password) VALUES ($1, $2)', [contact, hashedPassword]);
    }

    // Clear session contact
    req.session.contact = null;
    req.session.resetContact = null;

    res.redirect('/login');
  } catch (error) {
    console.error("Error setting password:", error);
    res.render('hotel/4_setPassAfterRegister.ejs', {
      contact,
      message: 'Something went wrong. Please try again.'
    });
  }
});


//phone otp send
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
function sendSMSOTP(phone, otp) {
  return twilioClient.messages.create({
    body: `Your Scan2Dine OTP is: ${otp}`,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: phone.startsWith('+') ? phone : '+91' + phone // assuming Indian numbers
  });
}

//login
app.post('/verify-password', async (req, res) => {
  const { loginInput, password } = req.body;

  try {
    let result;

    // Check if input is email or phone (basic check)
    if (loginInput.includes('@')) {
      result = await db.query('SELECT * FROM users WHERE contact = $1', [loginInput]);
    } else {
      // Normalize phone numbers: remove spaces, dashes, etc. (if needed)
      const cleanedPhone = loginInput.replace(/\D/g, '');
      result = await db.query('SELECT * FROM users WHERE contact = $1', [cleanedPhone]);
    }

    // If user not found
    if (result.rows.length === 0) {
      return res.render("hotel/5_login.ejs", { message: "User not found. Please check your input." });
    }

    const user = result.rows[0];

    // Compare hashed password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render("hotel/5_login.ejs", { message: "Incorrect password. Please try again." });
    }

    // Successful login (you may set session or redirect to dashboard)
    req.session.user = user.contact;
    // res.redirect('/dashboard'); // change this as per your app's flow
    res.render("hotel/6_homeOrDashboard.ejs")

  } catch (err) {
    console.error("Login error:", err);
    res.render("hotel/5_login.ejs", { message: "Something went wrong. Please try again later." });
  }
});


//forgot otp
app.get('/forgot-password', (req, res) => {
  res.render("hotel/7_forgotPassword.ejs", { message: null });
});
app.post('/forgot-password/send-otp', async (req, res) => {
  const { contact } = req.body;
  const otp = generateOTP();
  req.session.forgotOtp = otp;
  req.session.resetContact = contact;

  try {
    const user = await db.query('SELECT * FROM users WHERE contact = $1', [contact]);
    if (user.rows.length === 0) {
      return res.render("hotel/7_forgotPassword.ejs", { message: "User not found!" });
    }

    if (contact.includes('@')) {
      await sendEmailOTP(contact, otp);
    } else {
      await sendSMS(contact, otp); // Use Twilio
    }

    res.render("hotel/8_verifyForgotOTP.ejs", { message: "OTP sent. Please verify.", contact });
  } catch (err) {
    console.error("Error sending forgot password OTP:", err);
    res.render("hotel/7_forgotPassword.ejs", { message: "Error. Try again later." });
  }
});
app.post('/forgot-password/verify-otp', (req, res) => {
  const { otp } = req.body;
  const sessionOTP = req.session.forgotOtp;
  const contact = req.session.resetContact;

  if (!contact || !sessionOTP) {
    return res.redirect('/forgot-password');
  }

  if (otp === sessionOTP) {
    // OTP verified, move to password reset
    req.session.forgotOtp = null; // Clear OTP after use
    req.session.resetContact = contact;

    return res.render('hotel/4_setPassAfterRegister.ejs', {
      contact,
      message: null
    });
  } else {
    return res.render('hotel/8_verifyForgotOTP.ejs', {
      contact,
      message: 'Invalid OTP. Please try again.'
    });
  }
});



//Manage Kitchen(add food item)
app.get("/manage-menu", (req, res) => {
  res.render("hotel/9_addFoodItem.ejs", { message: null });
});
// app.post("/add-food-item", upload.single('image'), async (req, res) => {
//   const { name, description, price, category } = req.body;
//   const image = req.file ? `/imageUploads/${req.file.filename}` : null;
//   const contact = req.session.user;

//   if (!contact) {
//     return res.redirect("/login");
//   }

//   try {
//     // Get user_id from contact
//     const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
//     if (userResult.rows.length === 0) {
//       return res.redirect("/login");
//     }

//     const userId = userResult.rows[0].id;

//     // Insert into database
//     await db.query(
//       "INSERT INTO food_items (user_id, name, description, price, category, image_url) VALUES ($1, $2, $3, $4, $5, $6)",
//       [userId, name, description, price, category, image]
//     );

//     res.render("hotel/9_addFoodItem.ejs", { message: "Food item added successfully!" });

//   } catch (err) {
//     console.error("Error adding food item:", err);
//     res.render("hotel/9_addFoodItem.ejs", { message: "Something went wrong. Try again." });
//   }
// });
app.post("/add-food-item", upload.single("image"), async (req, res) => {
  const contact = req.session.user;
  const { name, description, price, category } = req.body;
  
  if (!contact) {
    return res.redirect("/login");
  }

  try {
    // Get logged-in user_id
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    if (userResult.rows.length === 0) {
      return res.redirect("/login");
    }
    const userId = userResult.rows[0].id;

    let imageUrl = null;

    if (req.file) {
      // Upload to Cloudinary directly from memory
      const streamUpload = (buffer) => {
        return new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: "scan2dine/menu-items" },
            (error, result) => {
              if (result) resolve(result);
              else reject(error);
            }
          );
          streamifier.createReadStream(buffer).pipe(stream);
        });
      };

      const result = await streamUpload(req.file.buffer);
      imageUrl = result.secure_url;
    }

    // Insert into DB
    // await db.query(
    //   "INSERT INTO food_items (user_id, name, description, price, availability, image_url) VALUES ($1, $2, $3, $4, $5, $6)",
    //   [userId, req.body.name, req.body.description, req.body.price, req.body.availability === "true", imageUrl]
    // );
    await db.query(
      "INSERT INTO food_items (user_id, name, description, price, category, image_url) VALUES ($1, $2, $3, $4, $5, $6)",
      [userId, name, description, price, category, imageUrl]
    );

    res.redirect("/display-menu");

  } catch (err) {
    console.error("Error adding food item:", err);
    res.status(500).send("Something went wrong.");
  }
});


//Display Menu
app.get("/display-menu", async (req, res) => {
  const contact = req.session.user;

  if (!contact) {
    return res.redirect("/login");
  }

  try {
    // Get user_id of the logged-in hotel manager
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);

    if (userResult.rows.length === 0) {
      return res.redirect("/login");
    }

    const userId = userResult.rows[0].id;

    // Fetch only available food items for this hotel manager
    const foodResult = await db.query(
      "SELECT * FROM food_items WHERE user_id = $1 AND availability = TRUE ORDER BY created_at DESC",
      [userId]
    );

    res.render("hotel/10_displayMenu.ejs", { foodItems: foodResult.rows });

  } catch (err) {
    console.error("Error displaying menu:", err);
    res.status(500).send("Something went wrong.");
  }
});


app.post("/mark-unavailable/:id", async (req, res) => {
  const contact = req.session.user;
  const itemId = req.params.id;

  if (!contact) {
    return res.redirect("/login");
  }

  if (!itemId) {
    return res.status(400).send("Missing item ID");
  }

  try {
    // Get user ID from contact
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    if (userResult.rows.length === 0) {
      return res.redirect("/login");
    }

    const userId = userResult.rows[0].id;

    // Verify if the item belongs to the logged-in user
    const itemResult = await db.query("SELECT * FROM food_items WHERE id = $1 AND user_id = $2", [itemId, userId]);
    if (itemResult.rows.length === 0) {
      return res.status(403).send("Unauthorized or item not found.");
    }

    // Update availability to false
    await db.query("UPDATE food_items SET availability = false WHERE id = $1", [itemId]);

    // Redirect back to menu
    res.redirect("/display-menu");

  } catch (err) {
    console.error("Error marking item as unavailable:", err);
    res.status(500).send("Internal server error");
  }
});
app.get("/update-item/:id", async (req, res) => {
  const contact = req.session.user;
  const itemId = req.params.id;

  if (!contact) return res.redirect("/login");

  try {
    // Get user ID
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    if (userResult.rows.length === 0) return res.redirect("/login");

    const userId = userResult.rows[0].id;

    // Fetch the food item
    const itemResult = await db.query("SELECT * FROM food_items WHERE id = $1 AND user_id = $2", [itemId, userId]);
    if (itemResult.rows.length === 0) return res.status(404).send("Item not found or unauthorized");

    res.render("hotel/11_updateItem.ejs", { item: itemResult.rows[0], message: null });

  } catch (err) {
    console.error("Error loading item:", err);
    res.status(500).send("Internal server error");
  }
});
app.post("/update-item-done/:id", upload.single("image"), async (req, res) => {
  const { name, description, price, category } = req.body;
  const newImage = req.file ? `/imageUploads/${req.file.filename}` : null;
  const contact = req.session.user;
  const itemId = req.params.id;

  if (!contact) {
    return res.redirect("/login");
  }

  try {
    // Get user ID
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    if (userResult.rows.length === 0) {
      return res.redirect("/login");
    }

    const userId = userResult.rows[0].id;

    // Ensure item belongs to user
    const itemResult = await db.query(
      "SELECT * FROM food_items WHERE id = $1 AND user_id = $2",
      [itemId, userId]
    );

    if (itemResult.rows.length === 0) {
      return res.status(403).send("Unauthorized or item not found.");
    }

    const oldImage = itemResult.rows[0].image_url;

    // Update DB
    if (newImage) {
      await db.query(
        "UPDATE food_items SET name = $1, description = $2, price = $3, category = $4, image_url = $5 WHERE id = $6",
        [name, description, price, category, newImage, itemId]
      );

      // Delete old image file (optional)
      if (oldImage) {
        const oldImagePath = "public" + oldImage;
        fs.unlink(oldImagePath, (err) => {
          if (err) console.warn("Old image not deleted:", err.message);
        });
      }
    } else {
      await db.query(
        "UPDATE food_items SET name = $1, description = $2, price = $3, category = $4 WHERE id = $5",
        [name, description, price, category, itemId]
      );
    }

    res.render("hotel/11_updateItem.ejs", { item: itemResult.rows[0], message:"Menu updated Successfully"});

  } catch (err) {
    console.error("Error updating food item:", err);
    res.status(500).send("Something went wrong while updating. Try again.");
  }
});




//profile 
app.get("/display-profile", async (req, res) => {
  const contact = req.session.user;

  if (!contact) {
    return res.redirect("/login");
  }

  try {
    // 1. Get user_id from contact
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    
    if (userResult.rows.length === 0) {
      console.error("User not found for contact:", contact);
      return res.redirect("/login");
    }

    const userId = userResult.rows[0].id;

    // 2. Get hotel details using user_id
    const hotelResult = await db.query(
      "SELECT * FROM hotel_details WHERE user_id = $1",
      [userId]
    );

    // 3. Render with hotel details if found
    if (hotelResult.rows.length > 0) {
      const hotel = hotelResult.rows[0];
      return res.render("hotel/12_profile.ejs", { hotel, message: null });
    } else {
      // No hotel details found yet
      return res.render("hotel/12_profile.ejs", { hotel: null, message: null });
    }

  } catch (err) {
    console.error("Error loading profile:", err);
    res.status(500).send("Something went wrong while loading profile.");
  }
});
app.get("/edit-profile", async (req, res) => {
  const contact = req.session.user;

  if (!contact) {
    return res.redirect("/login");
  }

  try {
    // 1. Get user_id from contact
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    
    if (userResult.rows.length === 0) {
      console.error("User not found for contact:", contact);
      return res.redirect("/login");
    }

    const userId = userResult.rows[0].id;

    // 2. Check if hotel details already exist for the user
    const hotelResult = await db.query(
      "SELECT * FROM hotel_details WHERE user_id = $1",
      [userId]
    );

    const hotel = hotelResult.rows.length > 0 ? hotelResult.rows[0] : null;

    // 3. Render the edit profile form with pre-filled data if available
    res.render("hotel/13_editProfile.ejs", { hotel, message: null });

  } catch (err) {
    console.error("Error loading edit profile page:", err);
    res.status(500).send("Something went wrong while loading edit profile page.");
  }
});
app.post('/save-profile', async (req, res) => {
  const contact = req.session.user;

  if (!contact) {
    return res.redirect("/login");
  }


  const {
    name,
    address,
    type,
    contact_number,
    email,
    description
  } = req.body;

  try {
    // 1. Get user_id from contact
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    
    if (userResult.rows.length === 0) {
      console.error("User not found for contact:", contact);
      return res.redirect("/login");
    }

    const userid = userResult.rows[0].id;
    // Check if a hotel profile already exists for this user
    const result = await db.query('SELECT * FROM hotel_details WHERE user_id = $1', [userid]);

    if (result.rows.length > 0) {
      // If exists: Update
      await db.query(
        `UPDATE hotel_details 
         SET name = $1, address = $2, type = $3, contact_number = $4, email = $5, description = $6
         WHERE user_id = $7`,
        [name, address, type, contact_number, email, description, userid]
      );

      res.redirect('/display-profile?message=' + encodeURIComponent('Hotel profile updated successfully!'));

    } else {
      // If not: Insert new
      await db.query(
        `INSERT INTO hotel_details (user_id, name, address, type, contact_number, email, description)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [userid, name, address, type, contact_number, email, description]
      );

      res.redirect('/display-profile?message=' + encodeURIComponent('Hotel profile created successfully!'));
    }

  } catch (err) {
    console.error('Error saving hotel profile:', err);
    res.status(500).send('An error occurred while saving hotel profile. Please try again.');
  }
});


//add table
app.get("/add-table",(req,res)=>{
  res.render("hotel/14_addTable.ejs");
})
// POST: Handle QR generation and DB insert
app.post("/add-table", ensureLoggedIn, async (req, res) => {
  const contact = req.session.user;

  try {
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    if (userResult.rows.length === 0) {
        console.error("User not found for contact:", contact);
        return res.redirect("/login");
    }

    const user_id = userResult.rows[0].id;
    const { table_no } = req.body;

    // FIXED: Use HTTP instead of HTTPS for localhost
    const qrData = `https://Scan2Dine-vvss.onrender.com/order?hotel_id=${user_id}&table_no=${table_no}`;
    const qrImage = await QRCode.toDataURL(qrData);

    await db.query(
        `INSERT INTO qr_codes (user_id, table_no, qr_image)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, table_no) DO NOTHING`,
        [user_id, table_no, qrImage]
    );

    res.redirect("/show-qr");
} catch (err) {
    console.error("QR generation failed:", err);
    res.status(500).send("An error occurred while generating QR.");
}

});




//show qr codes
// GET: Show QR codes for all tables of logged-in user
app.get("/show-qr", ensureLoggedIn, async (req, res) => {
  const contact = req.session.user;

  if (!contact) {
    return res.redirect("/login");
  }
  const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    
    if (userResult.rows.length === 0) {
      console.error("User not found for contact:", contact);
      return res.redirect("/login");
    }

    const user_id = userResult.rows[0].id;

  try {
    const result = await db.query(
      `SELECT table_no, qr_image FROM qr_codes WHERE user_id = $1 ORDER BY table_no`,
      [user_id]
    );
    res.render("hotel/15_showQR.ejs", { qrCodes: result.rows });
  } catch (err) {
    console.error("QR display failed:", err);
    res.status(500).send("Failed to load QR codes.");
  }
});



//display orders
app.get("/manager-orders", async (req, res) => {
  const contact = req.session.user;

  if (!contact) {
    return res.redirect("/login");
  }

  const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);

  if (userResult.rows.length === 0) {
    console.error("User not found for contact:", contact);
    return res.redirect("/login");
  }

  const user_id = userResult.rows[0].id;

  try {
    const ordersResult = await db.query(
      `SELECT id, session_id, hotel_id, table_no, items, total_amount, payment_method, status, created_at
       FROM orders
       WHERE hotel_id = $1 AND status IN ('pending', 'preparing')
       ORDER BY created_at DESC`,
      [user_id]
    );

    const orders = ordersResult.rows;

    res.render('hotel/20_display-orders.ejs', { orders });

  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).send("Unable to load orders.");
  }
});


// POST route: Update order status
app.post('/manager/orders/:orderId/status', async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const { status } = req.body;

    const allowedStatuses = ['pending', 'preparing', 'complete', 'cancelled'];
    if (!allowedStatuses.includes(status)) {
      return res.status(400).send("Invalid status value");
    }

    const contact = req.session.user;

    if (!contact) {
      return res.redirect("/login");
    }

    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    if (userResult.rows.length === 0) {
      console.error("User not found for contact:", contact);
      return res.redirect("/login");
    }

    const user_id = userResult.rows[0].id;

    const orderCheck = await db.query(
      `SELECT * FROM orders WHERE id = $1 AND hotel_id = $2`,
      [orderId, user_id]
    );

    if (orderCheck.rows.length === 0) {
      return res.status(403).send("Unauthorized or order not found.");
    }

    await db.query(
      `UPDATE orders SET status = $1 WHERE id = $2`,
      [status, orderId]
    );

    // Redirect back to the orders listing page
    res.redirect('/manager-orders');

  } catch (err) {
    console.error("Error updating order status:", err);
    res.status(500).send("Failed to update order status");
  }
});


//display filtered orders
app.post("/filter-history", async (req, res) => {
    const { status, dateFrom, dateTo, tableNo, minAmount } = req.body;
    
    try {
        // 1. SESSION AND AUTHENTICATION VALIDATION
        const contact = req.session.user;
        if (!contact) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "Please login to access order history",
                messageType: "error"
            });
        }

        // Get user_id from session/database
        const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
        if (userResult.rows.length === 0) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "User session invalid. Please login again.",
                messageType: "error"
            });
        }

        const userId = userResult.rows[0].id;

        // 2. PARAMETER VALIDATION
        
        // Validate status (required)
        if (!status || status.trim() === '') {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "Please select an order status",
                messageType: "error"
            });
        }

        const allowedStatuses = ['pending', 'preparing', 'complete', 'cancelled', 'all'];
        const sanitizedStatus = status.toLowerCase().trim();
        
        if (!allowedStatuses.includes(sanitizedStatus)) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: `Invalid status. Allowed values: ${allowedStatuses.join(', ')}`,
                messageType: "error"
            });
        }

        // Validate date range
        let fromDate = null;
        let toDate = null;
        
        if (dateFrom && dateFrom.trim() !== '') {
            fromDate = new Date(dateFrom.trim());
            if (isNaN(fromDate.getTime())) {
                return res.render("hotel/22_inputstatus.ejs", {
                    message: "Invalid 'From' date format",
                    messageType: "error"
                });
            }
        }

        if (dateTo && dateTo.trim() !== '') {
            toDate = new Date(dateTo.trim());
            if (isNaN(toDate.getTime())) {
                return res.render("hotel/22_inputstatus.ejs", {
                    message: "Invalid 'To' date format",
                    messageType: "error"
                });
            }
            
            // Set to end of day for 'To' date
            toDate.setHours(23, 59, 59, 999);
        }

        // Validate date range logic
        if (fromDate && toDate && fromDate > toDate) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "From date cannot be later than To date",
                messageType: "error"
            });
        }

        // Validate future dates
        const today = new Date();
        today.setHours(23, 59, 59, 999);
        
        if (fromDate && fromDate > today) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "From date cannot be in the future",
                messageType: "error"
            });
        }

        if (toDate && toDate > today) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "To date cannot be in the future",
                messageType: "error"
            });
        }

        // Validate table number
        let sanitizedTableNo = null;
        if (tableNo && tableNo.trim() !== '') {
            sanitizedTableNo = tableNo.toString().trim().substring(0, 50);
            
            // Basic alphanumeric validation
            if (!/^[a-zA-Z0-9]+$/.test(sanitizedTableNo)) {
                return res.render("hotel/22_inputstatus.ejs", {
                    message: "Table number should contain only letters and numbers",
                    messageType: "error"
                });
            }
        }

        // Validate minimum amount
        let minAmountValue = null;
        if (minAmount && minAmount.toString().trim() !== '') {
            minAmountValue = parseFloat(minAmount);
            
            if (isNaN(minAmountValue) || minAmountValue < 0 || minAmountValue > 1000000) {
                return res.render("hotel/22_inputstatus.ejs", {
                    message: "Minimum amount should be between 0 and 1,000,000",
                    messageType: "error"
                });
            }
        }

        // 3. BUILD DYNAMIC QUERY (ORDERS TABLE ONLY)
        let query = `
            SELECT 
                id,
                hotel_id,
                table_no,
                items,
                total_amount,
                payment_method,
                status,
                created_at
            FROM orders
            WHERE hotel_id = $1
        `;
        
        const queryParams = [userId];
        let paramCounter = 1;

        // Add status filter (if not 'all')
        if (sanitizedStatus !== 'all') {
            paramCounter++;
            query += ` AND status = $${paramCounter}`;
            queryParams.push(sanitizedStatus);
        }

        // Add date range filter
        if (fromDate) {
            paramCounter++;
            query += ` AND created_at >= $${paramCounter}`;
            queryParams.push(fromDate.toISOString());
        }

        if (toDate) {
            paramCounter++;
            query += ` AND created_at <= $${paramCounter}`;
            queryParams.push(toDate.toISOString());
        }

        // Add table filter
        if (sanitizedTableNo) {
            paramCounter++;
            query += ` AND LOWER(table_no) = LOWER($${paramCounter})`;
            queryParams.push(sanitizedTableNo);
        }

        // Add minimum amount filter
        if (minAmountValue !== null) {
            paramCounter++;
            query += ` AND total_amount >= $${paramCounter}`;
            queryParams.push(minAmountValue);
        }

        // Add ordering
        query += ` ORDER BY created_at DESC, id DESC`;

        // Add limit to prevent performance issues
        query += ` LIMIT 1000`;

        console.log("Filter query:", query);
        console.log("Filter params:", queryParams);

        // 4. EXECUTE QUERY
        const result = await db.query(query, queryParams);
        const orders = result.rows;

        // 5. VALIDATE AND PROCESS RESULTS
        const validOrders = orders.filter(order => {
            return order.id && 
                   order.total_amount !== null && 
                   order.total_amount !== undefined &&
                   order.status &&
                   allowedStatuses.slice(0, -1).includes(order.status) && // Exclude 'all'
                   order.created_at;
        });

        // Log if any orders were filtered out
        if (orders.length !== validOrders.length) {
            console.warn(`Filtered out ${orders.length - validOrders.length} invalid orders`);
        }

        // 6. CALCULATE STATISTICS (UPDATED - REVENUE ONLY FROM COMPLETED ORDERS)
        const completedOrders = validOrders.filter(o => o.status === 'complete');
        
        const statistics = {
            total: validOrders.length,
            pending: validOrders.filter(o => o.status === 'pending').length,
            preparing: validOrders.filter(o => o.status === 'preparing').length,
            complete: completedOrders.length,
            cancelled: validOrders.filter(o => o.status === 'cancelled').length,
            // Revenue calculations based only on completed orders
            totalAmount: completedOrders.reduce((sum, order) => sum + parseFloat(order.total_amount || 0), 0),
            averageAmount: completedOrders.length > 0 ? 
                completedOrders.reduce((sum, order) => sum + parseFloat(order.total_amount || 0), 0) / completedOrders.length : 0
        };

        // 7. PREPARE FILTER INFO FOR DISPLAY
        const filterInfo = {
            status: sanitizedStatus === 'all' ? 'All Statuses' : sanitizedStatus.charAt(0).toUpperCase() + sanitizedStatus.slice(1),
            dateRange: fromDate && toDate ? 
                `${fromDate.toDateString()} to ${toDate.toDateString()}` :
                fromDate ? `From ${fromDate.toDateString()}` :
                toDate ? `Until ${toDate.toDateString()}` : 'All Time',
            tableNo: sanitizedTableNo || 'All Tables',
            minAmount: minAmountValue !== null ? `₹${minAmountValue}+` : 'Any Amount'
        };

        // 8. GET HOTEL NAME (SEPARATE QUERY) - FIXED
        let hotelName = 'Your Hotel'; // Default fallback
        try {
            const hotelResult = await db.query("SELECT name FROM hotel_details WHERE user_id = $1", [userId]);
            if (hotelResult.rows.length > 0 && hotelResult.rows[0].name) {
                hotelName = hotelResult.rows.name; // FIXED: Added 
            }
        } catch (hotelErr) {
            console.warn("Could not fetch hotel name:", hotelErr.message);
            // Continue with default hotel name
        }

        // 9. PREPARE SUCCESS MESSAGE
        let message = null;
        let messageType = 'success';

        if (validOrders.length === 0) {
            message = sanitizedStatus === 'all' ? 
                "No orders found matching your criteria. Try adjusting the filters." :
                `No ${sanitizedStatus} orders found matching your criteria.`;
            messageType = 'info';
        } else {
            message = `Found ${validOrders.length} order${validOrders.length === 1 ? '' : 's'} matching your criteria.`;
        }

        // 10. RENDER RESULTS PAGE
        res.render("hotel/23_history.ejs", {
            orders: validOrders,
            statistics: statistics,
            filterInfo: filterInfo,
            hotelName: hotelName,
            message: message,
            messageType: messageType,
            appliedFilters: {
                status: sanitizedStatus,
                dateFrom: dateFrom,
                dateTo: dateTo,
                tableNo: sanitizedTableNo,
                minAmount: minAmountValue
            }
        });

    } catch (err) {
        // 11. COMPREHENSIVE ERROR HANDLING
        console.error("Error in /filter-history:", err);

        // Database connection errors (FIXED SYNTAX)
        if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "Database connection error. Please try again later.",
                messageType: "error"
            });
        }

        // Database query errors
        if (err.code) {
            switch (err.code) {
                case '42P01': // Table doesn't exist
                    return res.render("hotel/22_inputstatus.ejs", {
                        message: "Database configuration error. Please contact support.",
                        messageType: "error"
                    });
                
                case '42703': // Column doesn't exist  
                    return res.render("hotel/22_inputstatus.ejs", {
                        message: "Database schema error. Please contact support.",
                        messageType: "error"
                    });
                
                case '22P02': // Invalid input syntax
                    return res.render("hotel/22_inputstatus.ejs", {
                        message: "Invalid filter parameters. Please check your input.",
                        messageType: "error"
                    });
                
                case '23503': // Foreign key violation
                    return res.render("hotel/22_inputstatus.ejs", {
                        message: "Data integrity error. Please contact support.",
                        messageType: "error"
                    });
                
                default:
                    console.error("Database error code:", err.code, "Message:", err.message);
                    return res.render("hotel/22_inputstatus.ejs", {
                        message: "Database error occurred. Please try again.",
                        messageType: "error"
                    });
            }
        }

        // JSON parsing errors (if items column has invalid JSON)
        if (err.message && err.message.includes('JSON')) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "Data format error. Some order data may be corrupted.",
                messageType: "error"
            });
        }

        // Timeout errors
        if (err.message && err.message.includes('timeout')) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "Request timeout. The server is busy, please try again.",
                messageType: "error"
            });
        }

        // Session errors
        if (err.message && err.message.includes('session')) {
            return res.render("hotel/22_inputstatus.ejs", {
                message: "Session expired. Please refresh the page and try again.",
                messageType: "error"
            });
        }

        // Generic fallback
        return res.render("hotel/22_inputstatus.ejs", {
            message: "An unexpected error occurred. Please try again or contact support.",
            messageType: "error"
        });
    }
});





























app.get("/order", async (req, res) => {
    const { hotel_id, table_no } = req.query;

    try {
        console.log("Query params:", req.query);

        const hotelIdInt = Number(hotel_id);
        if (!hotel_id || isNaN(hotelIdInt) || hotelIdInt <= 0) {
            return res.status(400).send("Invalid hotel_id");
        }

        if (!table_no) {
            return res.status(400).send("Invalid table_no");
        }

        // Store hotel_id and table_no in session for order tracking
        req.session.hotel_id = hotelIdInt;
        req.session.table_no = table_no;

        // 1. Get hotel name
        const hotelResult = await db.query(
            "SELECT name FROM hotel_details WHERE user_id = $1",
            [hotelIdInt]
        );

        if (hotelResult.rows.length === 0) {
            return res.status(404).send("Hotel not found");
        }

        const hotelName = hotelResult.rows[0].name;

        // 2. Get menu for that hotel (only available items)
        const menuResult = await db.query(
            "SELECT id, name, description, price, category, image_url FROM food_items WHERE user_id = $1 AND availability = TRUE ORDER BY category, name",
            [hotelIdInt]
        );

        const menu = menuResult.rows;

        // 3. Render the menu EJS
        res.render("customer/16_orders.ejs", {
            hotelId: hotelIdInt,
            tableNo: table_no,
            sessionId: req.session.id,
            hotelName,
            menu
        });
    } catch (err) {
        console.error("Error in /order:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/order/filter", async (req, res) => {
    const { hotel_id, table_no, category } = req.query;
    
    try {
        // Debug logging
        console.log("Filter params:", req.query);
        
        // 1. PARAMETER VALIDATION
        
        // Validate hotel_id
        if (!hotel_id) {
            return res.status(400).send("Missing hotel_id parameter");
        }
        
        const hotelIdInt = Number(hotel_id);
        if (isNaN(hotelIdInt) || hotelIdInt <= 0) {
            return res.status(400).send("Invalid hotel_id. Must be a positive number.");
        }
        
        // Validate table_no
        if (!table_no || table_no.trim() === '') {
            return res.status(400).send("Missing or empty table_no parameter");
        }
        
        // Sanitize table_no (remove extra spaces, limit length)
        const sanitizedTableNo = table_no.toString().trim().substring(0, 50);
        if (sanitizedTableNo === '') {
            return res.status(400).send("Invalid table_no after sanitization");
        }
        
        // Validate category
        if (!category || category.trim() === '') {
            return res.status(400).send("Missing or empty category parameter");
        }
        
        // Define allowed categories (exact database values)
        const allowedCategories = ['Starter', 'Main Course', 'Roti', 'Dessert', 'Drinks', 'Other'];
        
        // URL decode the category (handles %20 for spaces)
        const decodedCategory = decodeURIComponent(category).trim();
        
        if (!allowedCategories.includes(decodedCategory)) {
            return res.status(400).send(`Invalid category. Allowed values: ${allowedCategories.join(', ')}`);
        }
        
        // 2. STORE SESSION DATA
        req.session.hotel_id = hotelIdInt;
        req.session.table_no = sanitizedTableNo;
        
        // 3. CHECK HOTEL EXISTS AND GET NAME
        const hotelResult = await db.query(
            "SELECT name FROM hotel_details WHERE user_id = $1",
            [hotelIdInt]
        );
        
        if (hotelResult.rows.length === 0) {
            return res.status(404).send("Hotel not found. Please check hotel_id.");
        }
        
        const hotelName = hotelResult.rows[0].name;
        
        // Validate hotel name exists
        if (!hotelName || hotelName.trim() === '') {
            return res.status(500).send("Hotel name is not properly configured");
        }
        
        // 4. GET FILTERED MENU ITEMS
        const menuQuery = `
            SELECT id, name, description, price, category, image_url, created_at
            FROM food_items 
            WHERE user_id = $1 
            AND availability = TRUE 
            AND category = $2
            ORDER BY created_at DESC, name ASC
        `;
        
        const menuResult = await db.query(menuQuery, [hotelIdInt, decodedCategory]);
        
        const menu = menuResult.rows;
        
        // 5. VALIDATE MENU ITEMS
        const validMenu = menu.filter(item => {
            // Basic validation for each menu item
            return item.id && 
                   item.name && 
                   item.name.trim() !== '' &&
                   item.price !== null && 
                   item.price !== undefined &&
                   item.price >= 0 &&
                   item.category &&
                   allowedCategories.includes(item.category);
        });
        
        // Log if any items were filtered out
        if (menu.length !== validMenu.length) {
            console.warn(`Filtered out ${menu.length - validMenu.length} invalid menu items for hotel ${hotelIdInt}`);
        }
        
        // 6. CHECK FOR POTENTIAL ISSUES
        
        // Check if hotel has any food items at all
        const totalItemsResult = await db.query(
            "SELECT COUNT(*) as count FROM food_items WHERE user_id = $1 AND availability = TRUE",
            [hotelIdInt]
        );
        
        const totalItems = parseInt(totalItemsResult.rows[0].count);
        
        // Provide helpful messages for empty results
        let message = null;
        if (validMenu.length === 0) {
            if (totalItems === 0) {
                message = "This restaurant hasn't added any menu items yet. Please contact the restaurant.";
            } else {
                message = `No items found in "${decodedCategory}" category. Try browsing "All Items" to see the full menu.`;
            }
        }
        
        // 7. RENDER THE PAGE
        res.render("customer/16_orders.ejs", {
            hotelId: hotelIdInt,
            tableNo: sanitizedTableNo,
            sessionId: req.session.id,
            hotelName: hotelName.trim(),
            menu: validMenu,
            currentCategory: decodedCategory,
            message: message,
            totalItemsCount: totalItems,
            filteredCount: validMenu.length
        });
        
    } catch (err) {
        // 8. COMPREHENSIVE ERROR HANDLING
        console.error("Error in /order/filter:", err);
        
        // Database connection errors
        if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND') {
            return res.status(500).send("Database connection error. Please try again later.");
        }
        
        // Database query errors
        if (err.code) {
            switch (err.code) {
                case '42P01': // Table doesn't exist
                    return res.status(500).send("Database configuration error. Please contact support.");
                
                case '42703': // Column doesn't exist  
                    return res.status(500).send("Database schema error. Please contact support.");
                
                case '23502': // NOT NULL violation
                    return res.status(400).send("Missing required data. Please check your request.");
                
                case '23503': // Foreign key violation
                    return res.status(400).send("Invalid hotel reference. Please check hotel_id.");
                
                case '22P02': // Invalid input syntax
                    return res.status(400).send("Invalid parameter format. Please check your input.");
                
                default:
                    console.error("Database error code:", err.code, "Message:", err.message);
                    return res.status(500).send("Database error occurred. Please try again.");
            }
        }
        
        // Timeout errors
        if (err.message && err.message.includes('timeout')) {
            return res.status(504).send("Request timeout. The server is busy, please try again.");
        }
        
        // Memory errors
        if (err.message && err.message.includes('out of memory')) {
            return res.status(507).send("Server is overloaded. Please try again later.");
        }
        
        // Session errors
        if (err.message && err.message.includes('session')) {
            return res.status(400).send("Session error. Please try refreshing the page.");
        }
        
        // Generic fallback
        return res.status(500).send("An unexpected error occurred. Please try again or contact support.");
    }
});



app.get("/add-again",async (req,res)=>{
  let hotel_id=req.session.hotel_id;
  let table_no=req.session.table_no;
  try {

        const hotelIdInt = Number(hotel_id);
        if (!hotel_id || isNaN(hotelIdInt) || hotelIdInt <= 0) {
            return res.status(400).send("Invalid hotel_id");
        }

        if (!table_no) {
            return res.status(400).send("Invalid table_no");
        }

        // 1. Get hotel name
        const hotelResult = await db.query(
            "SELECT name FROM hotel_details WHERE user_id = $1",
            [hotelIdInt]
        );

        if (hotelResult.rows.length === 0) {
            return res.status(404).send("Hotel not found");
        }

        const hotelName = hotelResult.rows[0].name;

        // 2. Get menu for that hotel (only available items)
        const menuResult = await db.query(
            "SELECT id, name, description, price, category, image_url FROM food_items WHERE user_id = $1 AND availability = TRUE ORDER BY category, name",
            [hotelIdInt]
        );

        const menu = menuResult.rows;

        // 3. Render the menu EJS
        res.render("customer/16_orders.ejs", {
            hotelId: hotelIdInt,
            tableNo: table_no,
            sessionId: req.session.id,
            hotelName,
            menu
        });
    } catch (err) {
        console.error("Error in /order:", err);
        res.status(500).send("Internal Server Error");
    }
})


// Ensure express.json() is used for parsing JSON payloads
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.post("/add-to-cart", (req, res) => {
  const { id, name, price, quantity } = req.body;

  if (!id || !name || !price) {
    return res.status(400).send("Missing required fields");
  }

  const qty = parseInt(quantity, 10);
  if (isNaN(qty) || qty <= 0) {
    return res.status(400).send("Invalid quantity");
  }

  if (!req.session.cart) {
    req.session.cart = [];
  }

  const existingItem = req.session.cart.find(item => item.id === parseInt(id));
  if (existingItem) {
    existingItem.qty += qty;
  } else {
    req.session.cart.push({
      id: parseInt(id),
      name,
      price: parseFloat(price),
      qty: qty,
    });
  }

  res.redirect("/cart");
});


app.get("/cart", (req, res) => {
    const cart = req.session.cart || [];
    const { hotel_id, table_no } = req.session;
    
    res.render("customer/17_cart.ejs", { 
        cart,
        hotel_id,
        table_no
    });
});

app.get("/checkout", (req, res) => {
    const cart = req.session.cart || [];
    const { hotel_id, table_no } = req.session;

    if (!hotel_id || !table_no) {
        return res.redirect("/");
    }

    if (cart.length === 0) {
        return res.redirect("/cart");
    }

    res.render("customer/18_payment.ejs", {
        cart,
        hotel_id,
        table_no
    });
});
// app.get("/cart", (req, res) => {
//   const cart = req.session.cart || [];
//   res.render("17_cart.ejs", { cart });
// });
app.post("/update-cart", (req, res) => {
  const cart = req.session.cart || [];

  for (let i = 0; i < cart.length; i++) {
    const qty = parseInt(req.body[`qty_${i}`]);
    const remove = req.body[`remove_${i}`];

    if (remove) {
      cart[i].qty = 0;
    } else if (!isNaN(qty)) {
      cart[i].qty = qty;
    }
  }

  // Remove items with qty 0
  req.session.cart = cart.filter((item) => item.qty > 0);

  res.redirect("/cart");
});

app.post("/place-order", async (req, res) => {
  try {
    const cart = req.session.cart || [];
    const { hotel_id, table_no } = req.session;
    const { payment_method } = req.body;

    if (!hotel_id || !table_no) {
      return res.status(400).send("Invalid session data. Please scan QR code again.");
    }

    if (cart.length === 0) {
      return res.redirect("/cart");
    }

    if (!payment_method) {
      return res.status(400).send("Payment method is required");
    }

    // Generate or reuse a valid UUID for this session
    if (!req.session.dbSessionId) {
      req.session.dbSessionId = uuidv4();
    }
    const session_id = req.session.dbSessionId;

    const hotelIdStr = hotel_id.toString();
    const tableNoStr = table_no.toString();
    const itemsJSON = JSON.stringify(cart);
    const total_amount = cart.reduce((acc, item) => acc + item.qty * item.price, 0);

    console.log("Checking existing active orders for this table...");

    // Check if there is any order with status 'pending' or 'preparing' on this table in this hotel
    const activeOrdersResult = await db.query(
      `SELECT id FROM orders
       WHERE hotel_id = $1 AND table_no = $2 AND status IN ('pending', 'preparing')`,
      [hotelIdStr, tableNoStr]
    );

    if (activeOrdersResult.rows.length > 0) {
      // An active order exists on this table; reject placing a new order
      return res.status(400).send("Cannot place a new order: previous order(s) on this table are still pending or preparing.");
    }

    console.log("No active orders found, placing new order...");

    // All checks passed – insert the new order
    await db.query(
      `INSERT INTO orders (session_id, hotel_id, table_no, items, total_amount, payment_method, status, created_at)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, NOW())`,
      [session_id, hotelIdStr, tableNoStr, itemsJSON, total_amount, payment_method, 'pending']
    );

    // Clear the cart after successful order placement
    req.session.cart = [];

    // Redirect to order tracking page
    res.redirect("/order-tracking");
  } catch (err) {
    console.error("Error placing order:", err);
    res.status(500).send("Something went wrong while placing your order.");
  }
});

// app.post("/place-order", async (req, res) => {
//   try {
//     const cart = req.session.cart || [];
//     const { hotel_id, table_no } = req.session;
//     const { payment_method } = req.body;

//     if (!hotel_id || !table_no) {
//       return res.status(400).send("Invalid session data. Please scan QR code again.");
//     }
//     if (cart.length === 0) {
//       return res.redirect("/cart");
//     }

//     const total_amount = cart.reduce((acc, item) => acc + item.qty * item.price, 0);

//     if (payment_method === "UPI") {
//       // Create Razorpay order
//       const order = await razorpay.orders.create({
//         amount: total_amount * 100, // in paise
//         currency: "INR",
//         payment_capture: 1
//       });

//       // Send Razorpay order details to frontend for payment
//       return res.render("customer/21_upi_payment.ejs", {
//         razorpayKeyId: process.env.RAZORPAY_KEY_ID,
//         orderId: order.id,
//         amount: total_amount,
//         hotel_id,
//         table_no
//       });
//     }

//     // COD flow (insert order directly)
//     const session_id = req.session.dbSessionId || uuidv4();
//     req.session.dbSessionId = session_id;

//     await db.query(
//       `INSERT INTO orders (session_id, hotel_id, table_no, items, total_amount, payment_method, status, created_at)
//        VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, NOW())`,
//       [session_id, hotel_id, table_no, JSON.stringify(cart), total_amount, payment_method, 'pending']
//     );

//     req.session.cart = [];
//     res.redirect("/order-tracking");

//   } catch (err) {
//     console.error("Error placing order:", err);
//     res.status(500).send("Something went wrong while placing your order.");
//   }
// });


// app.post("/confirm-upi-payment", async (req, res) => {
//   const { razorpay_payment_id, razorpay_order_id, razorpay_signature, hotel_id, table_no } = req.body;

//   const shasum = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET);
//   shasum.update(razorpay_order_id + "|" + razorpay_payment_id);
//   const digest = shasum.digest("hex");

//   if (digest !== razorpay_signature) {
//     return res.status(400).send("Payment verification failed");
//   }

//   // Insert order after payment verification
//   const session_id = uuidv4();
//   await db.query(
//     `INSERT INTO orders (session_id, hotel_id, table_no, items, total_amount, payment_method, status, created_at)
//      VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, NOW())`,
//     [session_id, hotel_id, table_no, JSON.stringify(req.session.cart), req.session.cart.reduce((acc, item) => acc + item.qty * item.price, 0), "UPI", 'pending']
//   );

//   req.session.cart = [];
//   res.json({ success: true });
//   res.redirect("/order-tracking");
// });


app.get("/order-tracking", async (req, res) => {
  try {
    const sessionId = req.session.dbSessionId;

    if (!sessionId) {
      return res.status(400).send("Session expired or invalid. Please place a new order.");
    }

    // Step 1: Get latest order for this session
    const ordersResult = await db.query(
      `SELECT table_no, status, hotel_id FROM orders
       WHERE session_id = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [sessionId]
    );

    if (ordersResult.rows.length === 0) {
      return res.status(404).send("No order found for this session.");
    }

    const order = ordersResult.rows[0];
    const hotelId = order.hotel_id;

    // Step 2: Get the hotel name from hotel_details using user_id = hotel_id
    const hotelResult = await db.query(
      `SELECT name FROM hotel_details WHERE user_id = $1`,
      [hotelId]
    );

    const hotel_name =
      hotelResult.rows.length > 0 ? hotelResult.rows[0].name : 'Unknown';

    res.render("customer/19_order-tracking.ejs", {
      table_no: order.table_no,
      status: order.status,
      hotel_name: hotel_name
    });
  } catch (err) {
    console.error("Error fetching order status:", err);
    res.status(500).send("Failed to get order tracking info.");
  }
});







app.listen(port, () => {
  console.log(`Server is running on https://localhost:${port}`);

});
