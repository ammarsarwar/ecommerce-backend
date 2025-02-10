import "reflect-metadata";
import { DataSource } from "typeorm";
import express, { Request, Response, NextFunction } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { Product } from "./entity/Product";
import { User } from "./entity/User";
import { z } from "zod";
import { Like, MoreThanOrEqual, LessThanOrEqual } from "typeorm";

// Define a schema for query parameters
const productQuerySchema = z.object({
  name: z.string().optional(), // Optional name filter
  minPrice: z.string().optional(), // Optional minimum price filter
  maxPrice: z.string().optional(), // Optional maximum price filter
});
// Load environment variables
dotenv.config();

const app = express();
app.use(express.json());

// Initialize the DataSource
const AppDataSource = new DataSource({
  type: "postgres",
  url: process.env.DATABASE_URL,
  synchronize: true, // Automatically sync database schema (only for development)
  logging: false,
  entities: [Product, User],
});

// Middleware to authenticate admin users
const authenticateAdmin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    res.status(401).json({ message: "No token provided" });
    return; // Ensure no value is returned
  }

  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as {
      userId: number;
      isAdmin: boolean;
    };
    if (!payload.isAdmin) {
      res.status(403).json({ message: "Not authorized as admin" });
      return; // Ensure no value is returned
    }
    next(); // Pass control to the next middleware/route handler
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
    return; // Ensure no value is returned
  }
};

// Connect to the database
AppDataSource.initialize()
  .then(async () => {
    console.log("Connected to the database!");

    // Define routes

    // Register a new user
    app.post("/register", async (req: Request, res: Response): Promise<any> => {
      const { username, password, isAdmin } = req.body;
      const userRepository = AppDataSource.getRepository(User);

      // Check if the user already exists
      const existingUser = await userRepository.findOneBy({ username });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create and save the new user
      const newUser = userRepository.create({
        username,
        password: hashedPassword,
        isAdmin,
      });
      const result = await userRepository.save(newUser);
      res.json(result);
    });

    // Log in
    app.post("/login", async (req: Request, res: Response): Promise<any> => {
      const { username, password } = req.body;
      const userRepository = AppDataSource.getRepository(User);

      // Find the user
      const user = await userRepository.findOneBy({ username });
      if (!user) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      // Compare passwords
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, isAdmin: user.isAdmin },
        process.env.JWT_SECRET!,
        { expiresIn: "1h" }
      );
      res.json({ token });
    });

    // Get all products
    app.get("/products", async (req, res) => {
      try {
        // Validate and parse query parameters
        const queryParams = productQuerySchema.parse(req.query);

        // Build a query object based on filters
        const query: Record<string, any> = {};
        if (queryParams.name) {
          query.name = Like(`%${queryParams.name}%`); // Use TypeORM's Like operator for case-insensitive search
        }
        if (queryParams.minPrice) {
          query.price = MoreThanOrEqual(parseFloat(queryParams.minPrice)); // Convert minPrice to a number
        }
        if (queryParams.maxPrice) {
          query.price = LessThanOrEqual(parseFloat(queryParams.maxPrice)); // Convert maxPrice to a number
        }

        const productRepository = AppDataSource.getRepository(Product);
        const products = await productRepository.find({ where: query }); // Apply filters

        res.json(products);
      } catch (error) {
        console.error("Error fetching products:", error); // Log detailed error
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Add a new product (Admin only)
    app.post(
      "/products",
      authenticateAdmin,
      async (req: Request, res: Response): Promise<any> => {
        const productRepository = AppDataSource.getRepository(Product);
        const newProduct = productRepository.create(req.body);
        const result = await productRepository.save(newProduct);
        res.json(result);
      }
    );

    // Update a product (Admin only)
    app.put(
      "/products/:id",
      authenticateAdmin,
      async (req: Request, res: Response): Promise<any> => {
        const productId = parseInt(req.params.id);
        const productRepository = AppDataSource.getRepository(Product);
        const product = await productRepository.findOneBy({ id: productId });
        if (!product)
          return res.status(404).json({ message: "Product not found" });

        productRepository.merge(product, req.body);
        const result = await productRepository.save(product);
        res.json(result);
      }
    );

    // Delete a product (Admin only)
    app.delete(
      "/products/:id",
      authenticateAdmin,
      async (req: Request, res: Response): Promise<any> => {
        const productId = parseInt(req.params.id);
        const productRepository = AppDataSource.getRepository(Product);
        const result = await productRepository.delete(productId);
        res.json(result);
      }
    );

    // Start the server
    app.listen(5000, () => {
      console.log("Server is running on http://localhost:5000");
    });
  })
  .catch((error) => {
    console.error("Error connecting to the database:", error);
  });
