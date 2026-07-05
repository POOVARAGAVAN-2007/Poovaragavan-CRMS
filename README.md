# Poovaragavan-CRMS
📋 Project Overview

The Crime Report Management System (CRMS) is a full-stack web application built at VSB Engineering College, Karur (2025-2026). It digitizes the crime reporting process, allowing citizens to file reports online, track case progress in real-time, and receive automatic notifications — while giving law enforcement officers and administrators powerful case management and analytics tools.

✅ The Solution

The system replaces the entire manual workflow with a secure digital platform featuring three user roles:
For Citizens:
 
Register and file crime reports online with detailed descriptions
 
Upload evidence (photos, videos, documents) via drag-and-drop
 
Track case status through a visual timeline of all updates
 
Receive real-time notifications when officers update their case
 
Search and filter their own reports
For Officers:
 
View only assigned cases on a personal dashboard
 
Add investigation notes and update case status
 
Upload evidence and examine citizen-submitted files
 
Automatic citizen notifications on every update
For Administrators:
 
Full system access: all reports, all users, all analytics
 
Manage user accounts, assign officers to cases, change roles
 
View dashboards with crime trends, resolution rates, and monthly comparisons
 
Access complete audit trails of all system activities

🏗️ Architecture & Technology

Component	Technology	Why It Was Chosen	
Frontend	HTML5, CSS3, JavaScript	Lightweight, fast loading, no build step needed, works on all devices	
Backend	Node.js + Express.js	Same language as frontend, handles many concurrent requests efficiently	
Database	PostgreSQL	Relational data with foreign keys, ACID compliance, complex query support	
Cache	Redis	Fast session storage and real-time notification queues	
Authentication	JWT + Bcrypt	Secure stateless tokens with hashed passwords	
File Uploads	Multer	Secure multipart handling with type/size validation	
Deployment	Docker + Nginx + PM2	Containerization, reverse proxy, and process clustering	


