# 🍽️ Scan2Dine – Contactless Restaurant Ordering System

## 📌 Overview
**Scan2Dine** is a **web-based contactless restaurant ordering system** designed for hotels and restaurants to provide a seamless dining experience.  
Customers can scan a **static QR code** placed on their table, view the menu, place orders, and pay — all without downloading an app or logging in.  
Hotel managers can easily **manage menus, tables, and order statuses** from an intuitive dashboard.

---

## Checkout Website Here : https://scanfeast-vvss.onrender.com
## Example QR code : 

## 🚀 Features

### 🛒 Customer Side
- 📱 **Static QR Code Ordering** – Scan once, order multiple times
- 📍 **Location Verification** – Orders only allowed from within the hotel
- 🍴 **Hotel-specific Menus** – View menu for the table scanned
- 🛍 **Cart Management** – Add/remove items before checkout
- 💳 **Multiple Payment Modes** – UPI or Cash on Delivery
- 🛑 **No Login Required** – Tracked via session cookies

### 🏨 Hotel Manager Side
- 🗂 **Menu Management** – Add, update, and delete food items
- 🪑 **Table QR Code Generation** – Static QR codes (one-time print per table)
- 📦 **Order Management** – View and update order statuses (Pending, Delivered)
- 🔐 **Secure Authentication** – OTP-based registration & password setup

---

## 🛠️ Tech Stack

**Frontend**
- HTML, CSS, JavaScript (EJS templating)
- Responsive UI for mobile & desktop

**Backend**
- Node.js & Express.js
- Session-based Authentication

**Database**
- PostgreSQL

**Other Tools**
- `qrcode` npm package for generating static QR codes
- `express-session` for tracking customer sessions
- Geolocation API for location-based order restrictions

---

## 📂 Project Structure

Scan2Dine/
│
├── public/ # Static files (CSS, JS, images)
├── views/ # EJS templates for frontend
├── routes/ # All server routes
├── index.js # Main server file
├── package.json
└── README.md


---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository
git clone https://github.com/your-username/scan2dine.git
cd scan2dine

### 2️⃣ Install dependencies
npm install

### 3️⃣ Configure environment variables
Create a .env file in the root directory and add:
PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_postgres_username
DB_PASSWORD=your_postgres_password
DB_NAME=scan2dine
SESSION_SECRET=your_secret_key

### 4️⃣ Setup PostgreSQL database
Run the SQL schema provided in db/schema.sql to create tables.

### 5️⃣ Start the server
node index.js
The app will run at: http://localhost:3000

## 🎯 Future Enhancements -
🌎 Geolocation verification

🔑 Mobile number login for hotels, 

📊 Sales analytics for hotels

💳 Integration with payment gateways (Razorpay, Stripe)

