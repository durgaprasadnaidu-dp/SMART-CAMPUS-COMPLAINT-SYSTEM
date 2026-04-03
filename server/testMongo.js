const User = require('./models/User');

const createTestUser = async () => {
  const user = new User({
    name: 'Test Student',
    email: 'test@student.com',
    password: '123456', // real app uses bcrypt
    role: 'student',
    department: 'CS'
  });
  await user.save();
  console.log('Test user saved!');
};

mongoose.connection.once('open', () => {
  createTestUser();
});