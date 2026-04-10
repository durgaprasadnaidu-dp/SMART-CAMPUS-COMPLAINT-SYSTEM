import React, { useState } from 'react';
import axios from 'axios';
import { useHistory } from 'react-router-dom';

const Register = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [name, setName] = useState('');
    const [role, setRole] = useState('student');
    const [department, setDepartment] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const history = useHistory();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');
        
        // Validate required fields
        if (!name.trim() || !email.trim() || !password.trim() || !department.trim()) {
            setError('All fields are required');
            return;
        }
        
        try {
            // 1. Register the user
            await axios.post('https://smart-campus-complaint-system-7efu.onrender.com/api/auth/register', { 
                email: email.trim(), 
                password, 
                name: name.trim(), 
                role, 
                department: department.trim() 
            });

            // 2. Redirect based on role
            if (role === 'student') {
                history.push('/login/student');
            } else if (role === 'staff') {
                history.push('/staff/dashboard');
            }
        } catch (err) {
            console.error('Registration error:', err);
            setError(err.response?.data?.message || 'Registration failed. Please try again.');
        }
    };

    return (
        <div className="d-flex justify-content-center align-items-center min-vh-100 bg-light">
            <div className="card shadow p-4" style={{ minWidth: 350, maxWidth: 400 }}>
                <h2 className="mb-4 text-center" style={{ color: 'var(--primary-blue)' }}>Register</h2>
                {error && <div className="alert alert-danger">{error}</div>}
                {success && <div className="alert alert-success">{success}</div>}
                <form onSubmit={handleSubmit} autoComplete="off">
                    <div className="mb-3">
                        <label className="form-label">Full Name</label>
                        <input
                            type="text"
                            className="form-control"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            autoComplete="name"
                            placeholder="Enter your full name"
                            required
                        />
                    </div>
                    <div className="mb-3">
                        <label className="form-label">Email Address</label>
                        <input
                            type="email"
                            className="form-control"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            autoComplete="email"
                            placeholder="Enter your email address"
                            required
                        />
                    </div>
                    <div className="mb-3">
                        <label className="form-label">Password</label>
                        <input
                            type="password"
                            className="form-control"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            autoComplete="new-password"
                            placeholder="Create a password"
                            minLength="6"
                            required
                        />
                    </div>
                    <div className="mb-3">
                        <label className="form-label">Role</label>
                        <select 
                            className="form-select" 
                            value={role} 
                            onChange={(e) => setRole(e.target.value)}
                            autoComplete="off"
                        >
                            <option value="student">Student</option>
                            <option value="staff">Staff</option>
                        </select>
                    </div>
                    <div className="mb-4">
                        <label className="form-label">{role === 'student' ? 'Department/Branch' : 'Department/Area'}</label>
                    <select
                        value={department}
                        onChange={(e) => setDepartment(e.target.value)}
                        className="form-select"
                    >
                    <option value="">
                        Select {role === 'student' ? 'Department/Branch' : 'Department/Area'}
                    </option>

                    {/* 🎓 STUDENT ONLY */}
                    {role === 'student' && (
                    <>
                        <option value="B.Tech.CSE">B.Tech.CSE</option>
                        <option value="B.Tech.CSE(AI&ML)">B.Tech.CSE(AI&ML)</option>
                        <option value="B.Tech.CSE(Blockchain)">B.Tech.CSE(Blockchain)</option>
                        <option value="B.Tech.CSE(Cyber Security)">B.Tech.CSE(Cyber Security)</option>
                        <option value="B.Tech.CSE(Data Analytics)">B.Tech.CSE(Data Analytics)</option>
                        <option value="B.Tech.CSE(Software Engineering)">B.Tech.CSE(Software Engineering)</option>
                        <option value="B.Tech.CSBS">B.Tech.CSBS</option>
                        <option value="B.Tech.ECE">B.Tech.ECE</option>
                        <option value="B.Tech.ECE(VLSI)">B.Tech.ECE(VLSI)</option>
                        <option value="B.Tech.ECE(Embedded Systems)">B.Tech.ECE(Embedded Systems)</option>
                        <option value="B.Tech.EEE">B.Tech.EEE</option>
                        <option value="B.Tech. Mechanica">B.Tech. Mechanica</option>
                        <option value="M.Tech">M.Tech</option>
                        <option value="BBA">BBA</option>
                        <option value="BBL">BBL</option>
                        <option value="PHD-STUDENT">PHD-STUDENT</option>
      
                    </>
                    )}

                    {/* 👨‍🏫 STAFF ONLY */}
                    {role === 'staff' && (
                    <>
                        <option value="SCOPE">SCOPE</option>
                        <option value="SENSE">SENSE</option>
                        <option value="SMEC">SMEC</option>
                        <option value="SAS">SAS</option>
                        <option value="VISH">VISH</option>
                        <option value="VSL">VSL</option>
                        <option value="VSB">VSB</option>
                        <option value="SoftSkills">SoftSkills</option>
                        <option value="PHD">PHD</option>
                        <option value="CDC">CDC</option>
                        <option value="CTS">CTS(Network & Wifi)</option>
                        <option value="PET">Physical Education Department</option>
                        <option value="Library">Library</option>
                        <option value="Hostel">Hostel</option>
                        <option value="Transport">Transport</option>
                        <option value="Mess">Mess</option>
                        <option value="Maintenance">Maintenance(SIS & 360)</option>
                    </>
                    )}
                    </select>
                    </div>
                    <button type="submit" className="btn btn-primary w-100 mb-2">Register</button>
                    <button type="button" className="btn btn-link w-100" onClick={() => history.push('/login/student')}>Already have an account? Login</button>
                </form>
            </div>
        </div>
    );
};

export default Register;


