import express from 'express';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';

const router = express.Router();

const todoSchema = new mongoose.Schema({
  text: { type: String, required: true },
  status: { type: String, enum: ['Todo', 'Done', 'Trash'], default: 'Todo' },
  userEmail: { type: String, required: true },
}, { timestamps: true });

const Todo = mongoose.model('Todo', todoSchema);

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

router.get('/todos', authenticateToken, async (req, res) => {
  const todos = await Todo.find({ userEmail: req.user.email });
  res.json(todos);
});


router.post('/todos', authenticateToken, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: 'Text is required' });
  const todo = await Todo.create({
    text,
    status: 'Todo',
    userEmail: req.user.email
  });
    res.status(201).json(todo);
});

router.patch('/todos/:id', authenticateToken, async (req, res) => {
  const { status } = req.body;
  const todo = await Todo.findOneAndUpdate(
    { _id: req.params.id, userEmail: req.user.email },
    { status },
    { new: true }
  );
  if (!todo) return res.sendStatus(404);
  res.json(todo);
});

router.delete('/todos/:id', authenticateToken, async (req, res) => {
  const deleted = await Todo.findOneAndDelete({ _id: req.params.id, userEmail: req.user.email });
  if (!deleted) return res.sendStatus(404);
  res.sendStatus(204);
});

export default router;
