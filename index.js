const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const dns = require("dns");
dns.setServers(["8.8.8.8"]);

const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

if (!process.env.MONGO_URI || !process.env.SMTP_USER || !process.env.SMTP_PASS || !jwtSecret) {
    throw new Error("MONGO_URI, SMTP_USER, SMTP_PASS, and JWT_SECRET must be configured");
}

app.use(cors({ origin: process.env.FRONTEND_ORIGIN || "http://localhost:5173" }));
app.use(express.json());

mongoose.connect(process.env.MONGO_URI).then(() => {
    console.log("Connected to MongoDB");
})
    .catch((err) => {
        console.log("Error connecting to MongoDB", err);
    });

const loginSchema = new mongoose.Schema({
    user: String,
    password: String,
});

const login = mongoose.model("login", loginSchema, "loginpass");

const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.replace("Bearer ", "");

    if (!token) {
        return res.status(401).send({ error: "Authentication required" });
    }

    try {
        req.user = jwt.verify(token, jwtSecret);
        next();
    } catch (err) {
        res.status(401).send({ error: "Invalid or expired token" });
    }
};

app.post("/getpass", (req, res) => {

    const inuser = req.body.user
    const inpass = req.body.pass

    login.findOne({ user: inuser }).then((data) => {
        if (!data) {
            return res.send(false)
        }

        if (inpass === data.password) {
            const token = jwt.sign({ user: data.user }, jwtSecret, { expiresIn: "1h" });
            res.send({ authenticated: true, token })
        }
        else {
            res.send(false)
        }
    })
        .catch((err) => {
            console.log(err)
            res.send(false)
        })

})

const historySchema = new mongoose.Schema({
    recipients: { type: [String], required: true },
    subject: { type: String, required: true },
    body: { type: String, required: true },
    status: { type: String, enum: ["pending", "sent", "failed"], default: "pending" },
    sentAt: { type: Date, default: Date.now },
});

const history = mongoose.model("history", historySchema, "historypage")

app.get("/history", requireAuth, async (req, res) => {
    try {
        const records = await history.find().sort({ sentAt: -1 });
        res.send(records);
    } catch (err) {
        console.log(err);
        res.status(500).send({ error: "Unable to load email history" });
    }
});

// Create a transporter

app.post("/sendmail", requireAuth, async (req, res) => {
    const msg = req.body.msg;
    const email = req.body.email;
    const recipients = req.body.recipients;
    const subject = req.body.subject;
    const emailList = [...(Array.isArray(email) ? email : [email]), ...(Array.isArray(recipients) ? recipients : [recipients])]
        .flatMap((recipient) => typeof recipient === "string" ? recipient.split(",") : [])
        .map((recipient) => recipient.trim())
        .filter(Boolean)
        .filter((recipient, index, list) => list.indexOf(recipient) === index);

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!subject?.trim() || !msg?.trim() || emailList.length === 0 || emailList.some((emailAddress) => !emailPattern.test(emailAddress))) {
        return res.status(400).send({ success: false, message: "Enter a subject, body, and valid recipient emails" });
    }

    let record;

    try {
        record = await history.create({
            recipients: emailList,
            subject: subject.trim(),
            body: msg.trim(),
        });

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
        });
        for (const recipient of emailList) {
            await transporter.sendMail({
                from: process.env.SMTP_USER,
                to: recipient,
                subject: subject.trim(),
                text: msg.trim(),
            });
        }

        await history.findByIdAndUpdate(record._id, { status: "sent" });
        res.send({ success: true });
    } catch (err) {
        console.log(err);
        if (record) {
            await history.findByIdAndUpdate(record._id, { status: "failed" });
        }
        res.status(502).send({ success: false, message: "Email delivery failed" });
    }


})


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});