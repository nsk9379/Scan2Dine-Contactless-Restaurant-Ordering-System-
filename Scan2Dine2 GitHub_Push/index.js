import express from "express"
import bodyParser from "body-parser"
import pg from "pg"

import nodemailer from "nodemailer"       //email otp
import twilio from 'twilio';              //phone otp
import crypto from "crypto"
import bcrypt from 'bcrypt';              //Password Security
import session from "express-session"     //
import dotenv from "dotenv";              //connecting .env file

import multer from "multer";
import path from "path";
import fs from "fs";

import QRCode from "qrcode"

import { v4 as uuidv4, validate as uuidValidate } from "uuid"
//to generate new UUID if session_id on customer side was string or it was not generated


dotenv.config();

const port=process.env.PORT|| 3000;
const app=express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//File upload (multer middleware)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = './public/imageUploads';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + '-' + file.originalname.replace(/\s+/g, '');
    cb(null, uniqueName);
  }
});
const upload = multer({ storage });


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
// const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
// function sendSMSOTP(phone, otp) {
//   return twilioClient.messages.create({
//     body: `Your Scan2Dine OTP is: ${otp}`,
//     from: process.env.TWILIO_PHONE_NUMBER,
//     to: phone.startsWith('+') ? phone : '+91' + phone // assuming Indian numbers
//   });
// }

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
app.post("/add-food-item", upload.single('image'), async (req, res) => {
  const { name, description, price, category } = req.body;
  const image = req.file ? `/imageUploads/${req.file.filename}` : null;
  const contact = req.session.user;

  if (!contact) {
    return res.redirect("/login");
  }

  try {
    // Get user_id from contact
    const userResult = await db.query("SELECT id FROM users WHERE contact = $1", [contact]);
    if (userResult.rows.length === 0) {
      return res.redirect("/login");
    }

    const userId = userResult.rows[0].id;

    // Insert into database
    await db.query(
      "INSERT INTO food_items (user_id, name, description, price, category, image_url) VALUES ($1, $2, $3, $4, $5, $6)",
      [userId, name, description, price, category, image]
    );

    res.render("hotel/9_addFoodItem.ejs", { message: "Food item added successfully!" });

  } catch (err) {
    console.error("Error adding food item:", err);
    res.render("hotel/9_addFoodItem.ejs", { message: "Something went wrong. Try again." });
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
    const qrData = `https://scanfeast-jrza.onrender.com/order?hotel_id=${user_id}&table_no=${table_no}`;
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
  console.log(`Server is running on http://localhost:${port}`);
});