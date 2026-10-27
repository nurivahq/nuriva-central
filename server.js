
"use strict";



require("dotenv").config();

const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const configureOwnerAuth = require("./owner-auth");

const app = express();

if (!process.env.DATABASE_URL || !process.env.OWNER_USERNAME || !process.env.OWNER_PASSWORD_HASH || !process.env.SESSION_SECRET) {
    throw new Error("NURIVA Central configuration is incomplete.");
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
   ssl: { rejectUnauthorized: true },
    connectionTimeoutMillis: 10000,
    max: 5
});

const { requireOwnerAuth, getOwnerAuthStatus } = configureOwnerAuth(app, pool);
const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

app.disable("x-powered-by");

app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    next();
});

// Serve the existing NURIVA Central frontend.
app.get("/", requireOwnerAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "centeral.html"));
});

app.get("/api/health", (req, res) => {
    res.json({
        service: "NURIVA Central",
        status: "running",
        timestamp: new Date().toISOString()
    });
});

app.get("/api/owner-auth/status", getOwnerAuthStatus);



app.get("/api/central/status", requireOwnerAuth, async (req, res) => {
    try {
        const [businessesResult, signupsResult] = await Promise.all([
            pool.query(`
                SELECT
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE active = 1)::int AS active
                FROM businesses
            `),

            pool.query(`
                SELECT COUNT(*)::int AS total
                FROM pending_signups
            `)
        ]);

        const businesses = businessesResult.rows[0];
        const signups = signupsResult.rows[0];

        return res.json({
            service: "NURIVA Central",
            digitalConnection: "connected",
            dataAvailable: true,
            lastUpdated: new Date().toISOString(),

            businesses: {
                total: businesses.total,
                active: businesses.active
            },

            pendingSignups: {
                total: signups.total
            }
        });
    } catch (error) {
        console.error("Central platform query failed:", {
            code: error.code,
            message: error.message
        });

        return res.status(503).json({
            service: "NURIVA Central",
            digitalConnection: "unavailable",
            dataAvailable: false,
            message: "Platform data could not be retrieved."
        });
    }
});

app.get("/api/central/cafes", requireOwnerAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                id,
                name,
                slug,
                active,
                created_at
            FROM businesses
            ORDER BY id DESC
        `);

        return res.json({
            dataAvailable: true,
            cafes: result.rows
        });
    } catch (error) {
        console.error("Central caf� account query failed:", {
            code: error.code,
            message: error.message
        });

        return res.status(503).json({
            dataAvailable: false,
            message: "Caf� account data could not be retrieved."
        });
    }
});


app.use("/api", (req, res) => {
    res.status(404).json({ error: "API endpoint not found" });
});

app.use((req, res) => {
    res.status(404).send("Page not found.");
});

app.use((err, req, res, next) => {
    console.error("Unhandled request error:", {
        method: req.method,
        path: req.path,
        message: err.message
    });

    if (res.headersSent) {
        return next(err);
    }

    return res.status(500).json({
        error: "An unexpected server error occurred."
    });
});

app.listen(PORT, HOST, () => {
    console.log(`NURIVA Central is running on http://localhost:${PORT}`);
});






