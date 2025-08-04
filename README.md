# Full-Stack User Authentication & Email Verification App

This is a full-stack web application built with React (frontend) and Node.js/Express (backend) that provides user authentication with secure registration, login, email verification, and password reset via OTP emails.

---

## Features

- User registration with password hashing (bcrypt)
- Login and logout with JWT authentication and secure cookies
- Email verification with OTP sent via email using Nodemailer
- Password reset with OTP email verification
- Responsive UI built with React
- Secure API endpoints with validation and error handling

---

## Technologies Used

- Frontend: React, React Router, Axios, Tailwind CSS (or your CSS framework)
- Backend: Node.js, Express, MongoDB (Mongoose), bcryptjs, jsonwebtoken
- Email: Nodemailer with SMTP (Brevo / Sendinblue)
- Others: dotenv for environment variables

---

## Getting Started

### Prerequisites

- Node.js and npm installed
- MongoDB database (local or cloud)
- SMTP email credentials (e.g., Brevo / Sendinblue)

### Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name
