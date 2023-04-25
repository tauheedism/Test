const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require("sequelize");

const sequelize = new Sequelize("square", "root", "Siddiqui@615", {
  dialect: "mysql",
  host: "localhost",
});

const User = sequelize.define("User", {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  dob: {
    type: DataTypes.DATEONLY,
    allowNull: false,
  },
});


const app = express();

app.use(bodyParser.json());

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, "secret", (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post("/api/user", async (req, res) => {
  try {
    const { email, password, name, dob } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashedPassword, name, dob });
    const accessToken = jwt.sign({ userId: user.id }, "secret");
    res.json({ accessToken });
  } catch (error) {
    res.status(401).json({ error: "Something goes wrong" });
  }
});


app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findByPk(userId);
    res.json(user);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.get("/api/user/:id", authenticateToken, async (req, res) => {
  const userId = req.params.id;
  try {
    const user = await User.findByPk(userId);
    res.json(user);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const users = await User.findAll();
    res.json(users);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.delete("/api/user/:id", authenticateToken, async (req, res) => {
  const userId = req.params.id;
  try {
    await User.destroy({ where: { id: userId } });
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


sequelize
  // .sync({ force: true })
  .sync()
  .then(() => {
    app.listen(3000, () => console.log("server started at 3000"));
  })
  .catch((err) => {
    console.log(err);
  });
