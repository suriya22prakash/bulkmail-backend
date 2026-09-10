const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { Resend } = require('resend');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

if (!process.env.MONGO_URI || !process.env.RESEND_API_KEY || !process.env.FROM_EMAIL || !jwtSecret) {
    throw new Error("MONGO_URI, RESEND_API_KEY, FROM_EMAIL, and JWT_SECRET must be configured");
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

// Resend client — sends over HTTPS (port 443), which avoids the SMTP port
// blocking that causes "Connection timeout" on Render and similar hosts.
const resend = new Resend(process.env.RESEND_API_KEY);

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
        return res.status(400).send({
            success: false,
            message: "Enter a subject, body, and valid recipient emails"
        });
    }

    let record;

    try {
        record = await history.create({
            recipients: emailList,
            subject: subject.trim(),
            body: msg.trim(),
        });

        // Send all emails at the same time via Resend's HTTP API
        const results = await Promise.allSettled(
            emailList.map((recipient) =>
                resend.emails.send({
                    from: process.env.FROM_EMAIL,
                    to: recipient,
                    subject: subject.trim(),
                    text: msg.trim(),
                })
            )
        );

        // Resend resolves successfully even on API-level errors, so check
        // both promise rejection and an `error` field in the resolved value
        const failed = results.filter(
            (result) => result.status === "rejected" || result.value?.error
        );

        if (failed.length > 0) {
            failed.forEach((f) => {
                if (f.status === "rejected") {
                    console.error("sendMail failed:", f.reason?.message || f.reason);
                } else {
                    console.error("sendMail failed:", f.value.error);
                }
            });

            await history.findByIdAndUpdate(record._id, {
                status: "failed"
            });

            return res.status(502).send({
                success: false,
                message: `${failed.length} email(s) failed to send`
            });
        }

        await history.findByIdAndUpdate(record._id, {
            status: "sent"
        });

        res.send({ success: true });

    } catch (err) {
        console.log(err);

        if (record) {
            await history.findByIdAndUpdate(record._id, {
                status: "failed"
            });
        }

        res.status(502).send({
            success: false,
            message: "Email delivery failed"
        });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});