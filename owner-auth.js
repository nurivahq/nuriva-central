"use strict";

const express = require("express");

const expressSession = require("express-session");
const { rateLimit } = require("express-rate-limit");
const PgSession = require("connect-pg-simple")(expressSession);
const bcrypt = require("bcrypt");
const path = require("path");
const crypto = require("crypto");

function configureOwnerAuth(app, pool) {
    const production = process.env.NODE_ENV === "production";


                const loginLimiter = rateLimit({
                windowMs: 15 * 60 * 1000,
                limit: 5,
                standardHeaders: "draft-8",
                legacyHeaders: false,
                message: "Too many login attempts. Please try again later."
            });

            

    if (production) {
        app.set("trust proxy", 1);
    }

    app.use(expressSession({
        name: "nuriva.central.sid",
        store: new PgSession({
            pool,
            tableName: "central_sessions",
            createTableIfMissing: true
        }),
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: production,
            maxAge: 8 * 60 * 60 * 1000
        }
    }));

    app.use(express.urlencoded({
        extended: false,
        limit: "10kb"
    }));

    app.get("/login", (req, res, next) => {
        if (req.session.ownerAuthenticated === true) {
            return res.redirect("/");
        }

        req.session.loginCsrfToken = crypto.randomBytes(32).toString("hex");

        req.session.save((err) => {
            if (err) return next(err);
            res.setHeader("Cache-Control", "no-store");
            res.sendFile(path.join(__dirname, "login.html"));
        });
    });

    app.get("/api/login-csrf", (req, res) => {
        if (!req.session.loginCsrfToken) {
            return res.status(403).json({
                error: "Reload the login page to initialize the form."
            });
        }

        res.setHeader("Cache-Control", "no-store");
        return res.json({ token: req.session.loginCsrfToken });
    });
   app.post("/login", loginLimiter, async (req, res) => {
        const submittedToken = req.body.csrfToken || "";
        const storedToken = req.session.loginCsrfToken || "";

        if (
            !submittedToken ||
            !storedToken ||
            submittedToken.length !== storedToken.length ||
            !crypto.timingSafeEqual(
                Buffer.from(submittedToken),
                Buffer.from(storedToken)
            )
        ) {
            return res.status(403).send("Login form expired. Please reload the login page.");
        }

        delete req.session.loginCsrfToken;

        const username = String(req.body.username || "");
        const password = String(req.body.password || "");

        if (
            username !== process.env.OWNER_USERNAME ||
            !process.env.OWNER_PASSWORD_HASH ||
            !password ||
            password.length > 1024
        ) {
            return res.status(401).send("Invalid username or password.");
        }

        let passwordMatches = false;

        try {
            passwordMatches = await bcrypt.compare(
                password,
                process.env.OWNER_PASSWORD_HASH
            );
        } catch {
            return res.status(503).send("Owner login is temporarily unavailable.");
        }

        if (!passwordMatches) {
            return res.status(401).send("Invalid username or password.");
        }

        req.session.regenerate((error) => {
            if (error) {
                console.error("Owner session creation failed.");
                return res.status(500).send("Login could not be completed. Please try again.");
            }

            req.session.ownerAuthenticated = true;
            req.session.ownerUsername = process.env.OWNER_USERNAME;

            req.session.save((saveError) => {
                if (saveError) {
                    console.error("Owner session save failed.");
                    return res.status(500).send("Login could not be completed. Please try again.");
                }

                return res.redirect("/");
            });
        });
    });

                        app.post("/logout", (req, res) => {
                    const submittedToken = req.body.csrfToken || "";
                    const storedToken = req.session?.logoutCsrfToken || "";

                    if (
                        !submittedToken ||
                        !storedToken ||
                        submittedToken.length !== storedToken.length ||
                        !crypto.timingSafeEqual(
                            Buffer.from(submittedToken),
                            Buffer.from(storedToken)
                        )
                    ) {
                        return res.status(403).send("Invalid logout request. Please reload the dashboard and try again.");
                    }

                    delete req.session.logoutCsrfToken;

                    req.session.destroy((error) => {
                        if (error) {
                            return res.status(500).send("Logout could not be completed. Please try again.");
                        }

                        res.clearCookie("nuriva.central.sid", {
                            httpOnly: true,
                            sameSite: "lax",
                            secure: production
                        });

                        return res.redirect("/login");
                    });
                });

    function requireOwnerAuth(req, res, next) {
        if (req.session && req.session.ownerAuthenticated === true) {
            return next();
        }

        if (req.path.startsWith("/api/")) {
            return res.status(401).json({
                error: "Owner authentication required."
            });
        }

        return res.redirect("/login");
    }


                            app.get("/api/logout-csrf", requireOwnerAuth, (req, res) => {
                if (!req.session.logoutCsrfToken) {
                    req.session.logoutCsrfToken = crypto.randomBytes(32).toString("hex");
                }

                res.setHeader("Cache-Control", "no-store");

                req.session.save((error) => {
                    if (error) {
                        return res.status(500).json({
                            error: "Unable to initialize logout protection."
                        });
                    }

                    return res.json({ token: req.session.logoutCsrfToken });
                });
            });

                function getOwnerAuthStatus(req, res) {
        return res.json({
            configured: Boolean(
                process.env.OWNER_USERNAME &&
                process.env.OWNER_PASSWORD_HASH &&
                process.env.SESSION_SECRET
            ),
            authenticated: Boolean(
                req.session &&
                req.session.ownerAuthenticated === true
            )
        });
    }


       return { requireOwnerAuth, getOwnerAuthStatus };
}

module.exports = configureOwnerAuth;



