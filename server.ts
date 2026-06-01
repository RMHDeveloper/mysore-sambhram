/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { Database } from "./src/server/db.ts";
import { 
  Resident, 
  Admin, 
  Notice, 
  Meeting, 
  Expense, 
  MaintenancePayment, 
  MaintenanceDue,
  FinanceSummary, 
  UsefulLink, 
  Feedback, 
  AssociationSettings,
  SessionUser
} from "./src/types.ts";

declare global {
  namespace Express {
    interface Request {
      user?: SessionUser;
    }
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Body parser with 50MB limits for base64 file uploads (e.g. QR, bills, links)
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));

  // Dynamic Auth Middleware
  // Simple token encoding/decoding using Base64 of user objects
  function getSessionUser(req: express.Request): SessionUser | null {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return null;
    }
    try {
      const token = authHeader.split(" ")[1];
      const decodedJson = Buffer.from(token, "base64").toString("utf-8");
      return JSON.parse(decodedJson) as SessionUser;
    } catch (e) {
      return null;
    }
  }

  // API authorization guards
  function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
    const user = getSessionUser(req);
    if (!user) {
      res.status(401).json({ error: "Unauthorized access" });
      return;
    }
    (req as any).user = user;
    next();
  }

  function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
    const user = getSessionUser(req);
    if (!user || user.role !== "admin") {
      res.status(403).json({ error: "Forbidden: Admin access required" });
      return;
    }
    (req as any).user = user;
    next();
  }

  // ==================== AUTH ENDPOINTS ====================

  app.post("/api/auth/login", (req, res) => {
    const { role, username, phone, password } = req.body;

    if (role === "admin") {
      const dbAdmins = Database.getAdmins();
      // Admin allows login with username OR email
      const matchedAdmin = dbAdmins.find(
        (a) => (a.username === username || a.email === username) && a.password === password
      );

      if (matchedAdmin) {
        if (matchedAdmin.status === "inactive") {
          res.status(403).json({ error: "Your admin account is inactive" });
          return;
        }
        const sessionPayload: SessionUser = {
          id: matchedAdmin.id,
          role: "admin",
          name: matchedAdmin.name,
          email: matchedAdmin.email
        };
        const token = Buffer.from(JSON.stringify(sessionPayload)).toString("base64");
        res.json({ token, user: sessionPayload });
      } else {
        res.status(401).json({ error: "Invalid admin credentials" });
      }
    } else {
      // Resident Login
      const dbResidents = Database.getResidents();
      const matchedResident = dbResidents.find(
        (r) => r.phone === phone && r.password === password
      );

      if (matchedResident) {
        if (matchedResident.status === "inactive") {
          res.status(403).json({ error: "Your resident profile is inactive. Contact committee." });
          return;
        }
        const sessionPayload: SessionUser = {
          id: matchedResident.id,
          role: "resident",
          name: matchedResident.name,
          phone: matchedResident.phone,
          flatNo: matchedResident.flatNo,
          block: matchedResident.block
        };
        const token = Buffer.from(JSON.stringify(sessionPayload)).toString("base64");
        res.json({ token, user: sessionPayload });
      } else {
        res.status(401).json({ error: "Invalid phone number or password" });
      }
    }
  });

  app.get("/api/auth/me", requireAuth, (req, res) => {
    res.json({ user: req.user });
  });

  // ==================== GENERAL SETTINGS ====================

  app.get("/api/settings", (req, res) => {
    res.json(Database.getSettings());
  });

  app.post("/api/settings", requireAdmin, (req, res) => {
    const updatedSettings = Database.updateSettings({
      associationName: req.body.associationName || "Mysore Sambhram RWA",
      logoUrl: req.body.logoUrl || "",
      contactEmail: req.body.contactEmail || "",
      paymentQR: req.body.paymentQR || "",
      bankDetails: {
        bankName: req.body.bankDetails?.bankName || "",
        accountNo: req.body.bankDetails?.accountNo || "",
        ifscCode: req.body.bankDetails?.ifscCode || "",
        holderName: req.body.bankDetails?.holderName || ""
      }
    });

    // Mirror to active notice list or system message
    res.json(updatedSettings);
  });

  // ==================== NOTICE MANAGEMENT ====================

  app.get("/api/notices", (req, res) => {
    const notices = [...Database.getNotices()].sort((a, b) => b.id.localeCompare(a.id));
    res.json(notices);
  });

  app.post("/api/notices", requireAdmin, (req, res) => {
    const { title, content } = req.body;
    if (!title || !content) {
      res.status(400).json({ error: "Title and content are required" });
      return;
    }

    const notices = Database.getNotices();
    const newNotice: Notice = {
      id: "ntc_" + Date.now(),
      title,
      content,
      date: new Date().toISOString().split("T")[0],
      author: req.user?.name || "Management Committee"
    };

    notices.unshift(newNotice);
    Database.save();
    res.status(201).json(newNotice);
  });

  app.delete("/api/notices/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const db = Database.load();
    const index = db.notices.findIndex((n) => n.id === id);
    if (index !== -1) {
      db.notices.splice(index, 1);
      Database.save();
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Notice not found" });
    }
  });

  // ==================== MEMBER MANAGEMENT ====================

  app.get("/api/residents", requireAdmin, (req, res) => {
    res.json(Database.getResidents());
  });

  app.post("/api/residents", requireAdmin, (req, res) => {
    const { name, phone, password, flatNo, block, role, status } = req.body;
    if (!name || !phone || !password || !flatNo || !block) {
      res.status(400).json({ error: "All resident fields are required" });
      return;
    }

    const residents = Database.getResidents();
    if (residents.some((r) => r.phone === phone)) {
      res.status(400).json({ error: "Phone number already registered to a resident" });
      return;
    }

    const newRes: Resident = {
      id: "res_" + Date.now(),
      name,
      phone,
      password,
      flatNo,
      block,
      role: role || "owner",
      status: status || "active",
      createdAt: new Date().toISOString()
    };

    residents.push(newRes);

    // If there is an active due for the current month, create a pending payment for them automatically
    const dues = Database.getDues();
    const payments = Database.getPayments();
    dues.forEach(due => {
      const alreadyHas = payments.some(p => p.residentId === newRes.id && p.month === due.month);
      if (!alreadyHas) {
        payments.push({
          id: "pay_" + Date.now() + "_" + Math.random().toString(36).substr(2, 4),
          residentId: newRes.id,
          residentName: newRes.name,
          flatNo: newRes.flatNo,
          block: newRes.block,
          month: due.month,
          amount: due.amount,
          dueDate: due.dueDate,
          status: "pending"
        });
      }
    });

    Database.save();
    res.status(201).json(newRes);
  });

  app.put("/api/residents/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const { name, phone, password, flatNo, block, role, status } = req.body;

    const residents = Database.getResidents();
    const resIdx = residents.findIndex((r) => r.id === id);

    if (resIdx !== -1) {
      const originalPhone = residents[resIdx].phone;
      if (phone !== originalPhone && residents.some((r) => r.phone === phone)) {
        res.status(400).json({ error: "Phone number already registered" });
        return;
      }

      residents[resIdx] = {
        ...residents[resIdx],
        name: name || residents[resIdx].name,
        phone: phone || residents[resIdx].phone,
        password: password || residents[resIdx].password,
        flatNo: flatNo || residents[resIdx].flatNo,
        block: block || residents[resIdx].block,
        role: role || residents[resIdx].role,
        status: status || residents[resIdx].status
      };

      // Cascade update basic names/flats inside active payment logs too
      const payments = Database.getPayments();
      payments.forEach(p => {
        if (p.residentId === id) {
          p.residentName = residents[resIdx].name;
          p.flatNo = residents[resIdx].flatNo;
          p.block = residents[resIdx].block;
        }
      });

      Database.save();
      res.json(residents[resIdx]);
    } else {
      res.status(404).json({ error: "Resident not found" });
    }
  });

  app.delete("/api/residents/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const db = Database.load();
    const resIdx = db.residents.findIndex((r) => r.id === id);
    if (resIdx !== -1) {
      // Rather than fully wiping, mark inactive or delete to keep payment logs integrated
      db.residents[resIdx].status = "inactive";
      Database.save();
      res.json({ success: true, message: "Resident deactivated" });
    } else {
      res.status(404).json({ error: "Resident not found" });
    }
  });

  // ==================== COMMITTEE MEMBERS (ADMIN MANAGED) ====================
  // Admins are the committee members. Add, edit, or toggle passwords.
  app.get("/api/admins", requireAdmin, (req, res) => {
    // Hide password hashes just in case
    const admins = Database.getAdmins().map(a => {
      const { password, ...rest } = a;
      return rest;
    });
    res.json(admins);
  });

  // ==================== MEETING MANAGEMENT ====================

  app.get("/api/meetings", (req, res) => {
    res.json(Database.getMeetings());
  });

  app.post("/api/meetings", requireAdmin, (req, res) => {
    const { title, date, location, agenda, minutes, attachmentName, attachmentData } = req.body;
    if (!title || !date || !location) {
      res.status(400).json({ error: "Title, date/time and location are required" });
      return;
    }

    const meetings = Database.getMeetings();
    const newMtg: Meeting = {
      id: "mtg_" + Date.now(),
      title,
      date,
      location,
      agenda: agenda || "",
      minutes: minutes || "Pending meeting completion.",
      attachmentName,
      attachmentData
    };

    meetings.unshift(newMtg);
    Database.save();
    res.status(201).json(newMtg);
  });

  app.put("/api/meetings/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const { title, date, location, agenda, minutes, attachmentName, attachmentData } = req.body;

    const meetings = Database.getMeetings();
    const idx = meetings.findIndex(m => m.id === id);
    if (idx !== -1) {
      meetings[idx] = {
        ...meetings[idx],
        title: title || meetings[idx].title,
        date: date || meetings[idx].date,
        location: location || meetings[idx].location,
        agenda: agenda || meetings[idx].agenda,
        minutes: minutes !== undefined ? minutes : meetings[idx].minutes,
        attachmentName: attachmentName !== undefined ? attachmentName : meetings[idx].attachmentName,
        attachmentData: attachmentData !== undefined ? attachmentData : meetings[idx].attachmentData
      };
      Database.save();
      res.json(meetings[idx]);
    } else {
      res.status(404).json({ error: "Meeting not found" });
    }
  });

  app.delete("/api/meetings/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const db = Database.load();
    const idx = db.meetings.findIndex(m => m.id === id);
    if (idx !== -1) {
      db.meetings.splice(idx, 1);
      Database.save();
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Meeting not found" });
    }
  });

  // ==================== EXPENSE MANAGEMENT ====================

  app.get("/api/expenses", requireAuth, (req, res) => {
    // Both residents & admins can view expenses
    res.json(Database.getExpenses());
  });

  app.post("/api/expenses", requireAdmin, (req, res) => {
    const { title, amount, date, category, paidTo, attachmentName, attachmentData } = req.body;
    if (!title || !amount || !date || !category || !paidTo) {
      res.status(400).json({ error: "Please enter title, amount, date, category, and paidTo" });
      return;
    }

    const expenses = Database.getExpenses();
    const newExp: Expense = {
      id: "exp_" + Date.now(),
      title,
      amount: Number(amount),
      date,
      category,
      paidTo,
      attachmentName,
      attachmentData
    };

    expenses.unshift(newExp);
    Database.save();
    res.status(201).json(newExp);
  });

  app.delete("/api/expenses/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const db = Database.load();
    const idx = db.expenses.findIndex(e => e.id === id);
    if (idx !== -1) {
      db.expenses.splice(idx, 1);
      Database.save();
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Expense not found" });
    }
  });

  // ==================== MAINTENANCE DUES & BILLING ====================

  app.get("/api/payments/dues", requireAuth, (req, res) => {
    res.json(Database.getDues());
  });

  // Creating monthly maintenance dues sets amount & dueDate, and triggers pending records for all active residents!
  app.post("/api/payments/dues", requireAdmin, (req, res) => {
    const { month, amount, dueDate } = req.body;
    if (!month || !amount || !dueDate) {
      res.status(400).json({ error: "Month (YYYY-MM), amount, and due date are required" });
      return;
    }

    const dues = Database.getDues();
    // Check duplication
    if (dues.some(d => d.month === month)) {
      res.status(400).json({ error: `Maintenance dues for ${month} already exist.` });
      return;
    }

    const newDue: MaintenanceDue = {
      id: "due_" + Date.now(),
      month,
      amount: Number(amount),
      dueDate
    };

    dues.unshift(newDue);

    // Dynamic generation for all residents
    const activeResidents = Database.getResidents().filter(r => r.status === "active");
    const payments = Database.getPayments();

    activeResidents.forEach(resObj => {
      payments.push({
        id: "pay_" + Date.now() + "_" + Math.random().toString(36).substr(2, 4),
        residentId: resObj.id,
        residentName: resObj.name,
        flatNo: resObj.flatNo,
        block: resObj.block,
        month: month,
        amount: Number(amount),
        dueDate: dueDate,
        status: "pending"
      });
    });

    Database.save();
    res.status(201).json(newDue);
  });

  // Get active payment dashboard
  app.get("/api/payments", requireAuth, (req, res) => {
    const payments = Database.getPayments();
    if (req.user?.role === "admin") {
      res.json(payments);
    } else {
      // Resident: only fetch their own flat's payments
      const myPayments = payments.filter((p) => p.residentId === req.user?.id);
      res.json(myPayments);
    }
  });

  // Submit/Update payments (Mark resident as paid / pending or add payment notes)
  app.put("/api/payments/:id", requireAuth, (req, res) => {
    const { id } = req.params;
    const { status, paymentNotes, txnId, paidAt } = req.body;

    const payments = Database.getPayments();
    const idx = payments.findIndex(p => p.id === id);

    if (idx === -1) {
      res.status(404).json({ error: "Payment record not found" });
      return;
    }

    const isAuthorized = req.user?.role === "admin" || payments[idx].residentId === req.user?.id;
    if (!isAuthorized) {
      res.status(403).json({ error: "Forbidden: You cannot access other flats' payment receipts" });
      return;
    }

    if (req.user?.role === "admin") {
      // Full power admin update
      payments[idx].status = status || payments[idx].status;
      payments[idx].paymentNotes = paymentNotes !== undefined ? paymentNotes : payments[idx].paymentNotes;
      payments[idx].txnId = txnId !== undefined ? txnId : payments[idx].txnId;
      payments[idx].paidAt = paidAt || payments[idx].paidAt || new Date().toISOString();
    } else {
      // Resident reported transaction (UPI submission / IMPS tracking)
      payments[idx].txnId = txnId;
      payments[idx].paymentNotes = paymentNotes || `Self-reported payment`;
      payments[idx].paidAt = new Date().toISOString();
      // Resident flags it, but wait — should it transition status or retain pending until verified?
      // "Mark residents as paid or pending" is an Admin duty. 
      // Residents can submit proof, then Admin verifies it. Or residents mark it paid with notes.
      // Let's set Status to 'paid' when self-submitting with Txn ID, and add note prefix so admins see it.
      payments[idx].status = "paid"; 
      payments[idx].paymentNotes += ` (Resident Reported)`;
    }

    Database.save();
    res.json(payments[idx]);
  });

  // ==================== FINANCE ARCHIVE & SUMMARIES ====================

  app.get("/api/finances", (req, res) => {
    res.json(Database.getFinances());
  });

  app.post("/api/finances", requireAdmin, (req, res) => {
    const { month, openingBalance, totalCollection, totalExpenses, closingBalance, reportName, reportData } = req.body;
    if (!month) {
      res.status(400).json({ error: "Month and fiscal details are required" });
      return;
    }

    const finances = Database.getFinances();
    const newFin: FinanceSummary = {
      id: "fin_" + Date.now(),
      month,
      openingBalance: Number(openingBalance || 0),
      totalCollection: Number(totalCollection || 0),
      totalExpenses: Number(totalExpenses || 0),
      closingBalance: Number(closingBalance || 0),
      reportName,
      reportData
    };

    finances.unshift(newFin);
    Database.save();
    res.status(201).json(newFin);
  });

  // ==================== USEFUL LINKS MANAGEMENT ====================

  app.get("/api/links", (req, res) => {
    res.json(Database.getLinks());
  });

  app.post("/api/links", requireAdmin, (req, res) => {
    const { title, url, category } = req.body;
    if (!title || !url || !category) {
      res.status(400).json({ error: "Link details are incomplete" });
      return;
    }

    const links = Database.getLinks();
    const newLnk: UsefulLink = {
      id: "lnk_" + Date.now(),
      title,
      url,
      category
    };

    links.push(newLnk);
    Database.save();
    res.status(201).json(newLnk);
  });

  app.put("/api/links/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const { title, url, category } = req.body;

    const links = Database.getLinks();
    const idx = links.findIndex(l => l.id === id);

    if (idx !== -1) {
      links[idx] = {
        ...links[idx],
        title: title || links[idx].title,
        url: url || links[idx].url,
        category: category || links[idx].category
      };
      Database.save();
      res.json(links[idx]);
    } else {
      res.status(404).json({ error: "Link not found" });
    }
  });

  app.delete("/api/links/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const db = Database.load();
    const idx = db.links.findIndex(l => l.id === id);
    if (idx !== -1) {
      db.links.splice(idx, 1);
      Database.save();
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Link not found" });
    }
  });

  // ==================== FEEDBACK & COMPLAINTS ====================

  app.get("/api/feedback", requireAuth, (req, res) => {
    const feedbacks = Database.getFeedbacks();
    if (req.user?.role === "admin") {
      res.json(feedbacks);
    } else {
      // Resident sees only their feedback
      res.json(feedbacks.filter(f => f.residentId === req.user?.id));
    }
  });

  app.post("/api/feedback", requireAuth, (req, res) => {
    const { category, message, imageData } = req.body;
    if (!category || !message) {
      res.status(400).json({ error: "Category and message fields are required" });
      return;
    }

    const feedbacks = Database.getFeedbacks();
    const freshFb: Feedback = {
      id: "fbk_" + Date.now(),
      residentId: req.user?.id || "anonymous",
      residentName: req.user?.name || "Resident",
      flatNo: req.user?.flatNo || "N/A",
      category,
      message,
      imageData, // base64 string
      date: new Date().toISOString().split("T")[0],
      status: "open"
    };

    feedbacks.unshift(freshFb);
    Database.save();

    // Mock "sending feedback to admin and email" via server console alert
    console.log(`[EMAIL SEND] New Feedback from Resident: ${freshFb.residentName} (${freshFb.flatNo})`);
    console.log(`To: admin@mysoresambhramrwa.in, ${Database.getSettings().contactEmail}`);
    console.log(`Subject: [RWA Feedback/Complaint] ${category} - Flat ${freshFb.flatNo}`);
    console.log(`Body: ${message}`);

    res.status(201).json(freshFb);
  });

  app.put("/api/feedback/:id/resolve", requireAdmin, (req, res) => {
    const { id } = req.params;
    const { adminNotes } = req.body;

    const feedbacks = Database.getFeedbacks();
    const idx = feedbacks.findIndex(f => f.id === id);

    if (idx !== -1) {
      feedbacks[idx].status = "resolved";
      feedbacks[idx].adminNotes = adminNotes || "Marked resolved by Admin.";
      Database.save();
      res.json(feedbacks[idx]);
    } else {
      res.status(404).json({ error: "Feedback item not found" });
    }
  });

  // ==================== VITE MIDDLEWARE INTERCEPT ====================

  if (process.env.NODE_ENV !== "production") {
    // Development server
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    // Production serving
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*all", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
