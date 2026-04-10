import React, { useEffect, useState } from 'react';
import axios from 'axios';

const statusColors = {
  'pending': 'secondary',
  'in-progress': 'warning',
  'resolved': 'success'
};

const AdminDashboard = () => {

  const [complaints, setComplaints] = useState({
    pending: [],
    inProgress: [],
    resolved: []
  });

  const [staffList, setStaffList] = useState([]);
  const [search, setSearch] = useState('');
  const [notesEdit, setNotesEdit] = useState({});
  const [statusEdit, setStatusEdit] = useState({});
  const [workerType, setWorkerType] = useState({});
  const [selectedAssign, setSelectedAssign] = useState({});

  useEffect(() => {
    fetchComplaints();
    fetchStaff();
  }, []);

  // ✅ Fetch complaints
  const fetchComplaints = async () => {
    try {
      const res = await axios.get('https://smart-campus-complaint-system-7efu.onrender.com/api/complaints', {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });

      setComplaints({
        pending: res.data.pending || [],
        inProgress: res.data.inProgress || [],
        resolved: res.data.resolved || []
      });

    } catch (err) {
      console.error('Error fetching complaints');
    }
  };

  // ✅ Fetch staff
  const fetchStaff = async () => {
    try {
      const res = await axios.get('https://smart-campus-complaint-system-7efu.onrender.com/api/auth/staff', {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setStaffList(res.data);
    } catch {
      setStaffList([]);
    }
  };

  // ✅ Assign staff
  const handleAssign = async (complaintId, staffId) => {
    if (!staffId) return alert("Select staff");

    try {
      await axios.put(
        `https://smart-campus-complaint-system-7efu.onrender.com/api/complaints/${complaintId}/assign`,
        { staffId },
        {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        }
      );

      fetchComplaints();
    } catch {
      alert("Assign failed");
    }
  };

  // ✅ Status change
  const handleStatusChange = (id, status) => {
    setStatusEdit(prev => ({ ...prev, [id]: status }));
  };

  // ✅ Notes change
  const handleNotesChange = (id, notes) => {
    setNotesEdit(prev => ({ ...prev, [id]: notes }));
  };

  // ✅ Update (status + assign)
  const handleStatusUpdate = async (id) => {
    await axios.put(
      `https://smart-campus-complaint-system-7efu.onrender.com/api/complaints/${id}/status`,
      {
        status: statusEdit[id],
        resolutionNotes: notesEdit[id],
        assignedTo: selectedAssign[id]
      },
      {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      }
    );

    fetchComplaints();
  };

  // ✅ Show only pending + in-progress
  const allActiveComplaints = [
    ...(complaints.pending || []),
    ...(complaints.inProgress || [])
  ];

  const filteredComplaints = allActiveComplaints.filter(c =>
    c.title.toLowerCase().includes(search.toLowerCase()) ||
    c.status.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="container py-4">
      <h2>Admin Complaint Dashboard</h2>

      <input
        className="form-control mb-3"
        placeholder="Search..."
        value={search}
        onChange={e => setSearch(e.target.value)}
      />

      <table className="table table-bordered">
        <thead>
          <tr>
            <th>Title</th>
            <th>Status</th>
            <th>Category</th>
            <th>Assigned To</th>
            <th>Worker Type</th>
            <th>Assign Staff</th>
            <th>Status Update</th>
            <th>Notes</th>
          </tr>
        </thead>

        <tbody>
          {filteredComplaints.map(c => (
            <tr key={c._id}>
              <td>{c.title}</td>

              <td>
                <span className={`badge bg-${statusColors[c.status]}`}>
                  {c.status}
                </span>
              </td>

              <td>{c.category}</td>

              <td>{c.assignedTo?.email || 'Unassigned'}</td>

              {/* Worker Type */}
              <td>
                <select
                  className="form-select"
                  value={workerType[c._id] || ''}
                  onChange={(e) =>
                    setWorkerType(prev => ({
                      ...prev,
                      [c._id]: e.target.value
                    }))
                  }
                >
                  <option value="">Select Type</option>
                  <option value="SCOPE">SCOPE</option>
                  <option value="SENSE">SENSE</option>
                  <option value="SMEC">SMEC</option>
                  <option value="SAS">SAS</option>
                  <option value="PHD">PHD</option>
                  <option value="Hostel">Hostel</option>
                  <option value="Transport">Transport</option>
                  <option value="Mess">Mess</option>
                </select>
              </td>

              {/* Assign Staff */}
              <td>
                <select
                  className="form-select"
                  value={selectedAssign[c._id] || ''}
                  onChange={(e) =>
                    setSelectedAssign(prev => ({
                      ...prev,
                      [c._id]: e.target.value
                    }))
                  }
                >
                  <option value="">Select Staff</option>

                  {staffList
                    .filter(staff => {
                      if (!workerType[c._id]) return true;
                      return (
                        staff.department?.toLowerCase() ===
                        workerType[c._id].toLowerCase()
                      );
                    })
                    .map(staff => (
                      <option key={staff._id} value={staff._id}>
                        {staff.name}
                      </option>
                    ))}
                </select>

                <button
                  className="btn btn-primary btn-sm mt-2"
                  onClick={() => handleAssign(c._id, selectedAssign[c._id])}
                  disabled={!selectedAssign[c._id]}
                >
                  Assign
                </button>
              </td>

              {/* Status */}
              <td>
                <select
                  className="form-select"
                  value={statusEdit[c._id] || c.status}
                  onChange={e => handleStatusChange(c._id, e.target.value)}
                >
                  <option value="pending">Pending</option>
                  <option value="in-progress">In Progress</option>
                  <option value="resolved">Resolved</option>
                </select>

                <button
                  className="btn btn-success btn-sm mt-1"
                  onClick={() => handleStatusUpdate(c._id)}
                >
                  Update
                </button>
              </td>

              {/* Notes */}
              <td>
                <input
                  className="form-control"
                  value={notesEdit[c._id] || c.resolutionNotes || ''}
                  onChange={e => handleNotesChange(c._id, e.target.value)}
                />
              </td>

            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default AdminDashboard;