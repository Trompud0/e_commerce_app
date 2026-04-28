const express = require('express');
const db = require('./db.js');
const app = express();
const port = 3000;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'E-commerce API',
      version: '1.0.0',
      description: 'A PERN stack API for a Codecademy portfolio project',
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./app.js'], // Use the filename where your routes are located
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

//This Secret Key is mixed with the unique info of the user
//That way, each newly created token is unique 
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());


//Authentication middleware
function authenticateToken(req, res, next) {
  // Get the token from the header
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (token == null) {
    return res.status(401).json({ message: "No token provided" });
  }

  // Verify the token using the secret key
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    // Attach the decoded user data to the request object
    req.user = user; 
    
    next(); 
  });
}

app.get('/', (req, res) => {
  res.send('Hello World!')
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
});

// Registration Route
/**
 * @swagger
 * /registration:
 *   post:
 *     summary: Register a new account
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username: { type: string }
 *               email: { type: string }
 *               password: { type: string }
 *               phone: { type: string }
 *               address: { type: string }
 *     responses:
 *       201:
 *         description: Registered successfully
 */

app.post('/registration', async (req, res, next) => {
  try {
    const { username, email, password, phone, address } = req.body;

    // If any field missing
    if (!username || !email || !password || !phone || !address) {
      return res.status(400).json({ message: "Fill in all fields" });
    }
    
    // If user already exists
    const userCheck = await db.query('SELECT * FROM customers WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Hash the password
    // The number 10 is the "salt rounds" (how much processing power to use)
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Putting data into db
    // Insert the new customer into the database
    const newUser = await db.query(
      `INSERT INTO customers (username, email, password, phone, address) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, username, email`, // Don't return the password!
      [username, email, hashedPassword, phone, address]
    );

    res.status(201).json(newUser.rows[0]);

  } catch (error) {
     res.status(500).json({ message: "Error creating customer profile", error: error.message })
  }
});

//Login Route
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in to get a JWT token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username: { type: string }
 *               password: { type: string }
 *     responses:
 *       200:
 *         description: Login successful
 */

app.post('/login', async (req, res, next) => {
  try {
    const {username, password} = req.body;   

    //User check
    const userCheck = await db.query('SELECT * FROM customers WHERE username = $1', [username]);
    if (userCheck.rows.length === 0) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    const user = userCheck.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    // "Sign" a token containing the user's ID
    const token = jwt.sign(
      { id: user.id, username: user.username }, 
      JWT_SECRET, 
      { expiresIn: '1h' } // Token expires in 1 hour
    );

    res.status(200).json({
      message: "Login successful",
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    res.status(500).json({ message: "Error accessing customer profile", error: error.message })
  }
});


// Reviews Routes
/**
 * @swagger
 * /products/{productId}/reviews:
 *   get:
 *     summary: Get all reviews for a specific product
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: productId
 *         required: true
 *         description: The ID of the product to fetch reviews for
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: An array of reviews with customer usernames
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id: { type: integer }
 *                   rating: { type: integer }
 *                   review_text: { type: string }
 *                   username: { type: string }
 *       500:
 *         description: Server error
 */

app.get('/products/:productId/reviews', async (req, res, next) => {
   try {
     const queryText = `
       SELECT 
         reviews.*, 
         customers.username 
       FROM reviews 
       INNER JOIN customers ON reviews.customer_id = customers.customer_id 
       WHERE reviews.product_id = $1
       ORDER BY reviews.review_date DESC
     `;

     const result = await db.query(queryText, [req.params.productId]);
     res.json(result.rows);
   } catch (error) {
     res.status(500).json({ message: "Error fetching reviews", error: error.message });
   }
});


//Customers should see their profile information, login , etc
/**
 * @swagger
 * /profile:
 *   get:
 *     summary: View current user's profile
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully retrieved profile
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id: { type: integer }
 *                 username: { type: string }
 *                 email: { type: string }
 *                 phone: { type: string }
 *                 address: { type: string }
 *       404:
 *         description: Customer profile not found
 *       401:
 *         description: No token provided
 */



app.get('/profile', authenticateToken, async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        id, 
        username, 
        email, 
        phone, 
        address 
      FROM customers 
      WHERE id = $1
    `;
    
    const result = await db.query(queryText, [req.user.id]);

    // If no customer is found with that ID
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Customer profile not found" });
    }

    // Send just the single customer object
    res.json(result.rows[0]);
    
  } catch (error) {
    res.status(500).json({ message: "Error fetching customer profile", error: error.message });
  }
});

/**
 * @swagger
 * /profile:
 *   put:
 *     summary: Update customer profile information
 *     tags: [profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       description: Provide any fields you wish to update. Unprovided fields will remain unchanged.
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *               phone:
 *                 type: string
 *               address:
 *                 type: string
 *             example:
 *               phone: "555-0199"
 *               address: "123 New Street, Tech City"
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

app.put('/profile', authenticateToken, async (req, res, next) => {
  try {
    const {username, email, phone, address} = req.body;

    // COALESCE checks for first non null value. 
    // If user only updates phone, then other values won't be forgotten.
    // Will just keep the values that exist and only changes the new value
    const queryText = `
      UPDATE customers 
      SET 
        username = COALESCE($1, username), 
        email    = COALESCE($2, email), 
        phone    = COALESCE($3, phone), 
        address  = COALESCE($4, address) 
      WHERE id = $5 
      RETURNING id, username, email, phone, address
    `;

    // Translates so that SQL and JS work together. SQL knows null, not undefined
    // If username or any entry undefined, will substitute with null
    // This lets COALESCE work properly for partial updates.
    const values = [
      username || null, 
      email || null, 
      phone || null, 
      address || null, 
      req.user.id
    ];

    const result = await db.query(queryText, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "Profile updated!", user: result.rows[0] });

  } catch (error) {
    res.status(500).json({ message: "Error updating profile", error: error.message });
  }
});


//Categories
/**
 * @swagger
 * /categories/{categoryId}:
 *   get:
 *     summary: Get category by ID
 *     tags: [categories]
 *     parameters:
 *       - in: path
 *         name: categoryId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Category details
 *       404:
 *         description: Category not found
 */


app.get('/categories/:categoryId', async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        id, 
        category_name, 
        category_description
      FROM categories 
      WHERE id = $1
    `;

    const result = await db.query(queryText, [req.params.categoryId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json(result.rows[0]);

    } catch (error) {
    res.status(500).json({ message: "Error fetching category", error: error.message });
  }
});

/**
 * @swagger
 * /categories:
 *   get:
 *     summary: Get all categories
 *     tags: [categories]
 *     responses:
 *       200:
 *         description: A list of categories
 */

app.get('/categories', async (req, res, next) => {
  try {
    const queryText = `
      SELECT *
      FROM categories
    `;
    const result = await db.query(queryText);

    res.json(result.rows);

  } catch (error) {
    res.status(500).json({ message: "Error fetching categories", error: error.message });
  }
});

/**
 * @swagger
 * /categories/{categoryId}/products:
 *   get:
 *     summary: Get all products in a specific Category
 *     tags: [categories]
 *     parameters:
 *       - in: path
 *         name: categoryId
 *         required: true
 *         description: The ID of the category to filter products by
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: A list of products in this category
 *       404:
 *         description: No products found for this category
 */

app.get('/categories/:categoryId/products', async (req, res, next) => {
  try {
    const {categoryId} = req.params;

    const queryText = `
      SELECT *
      FROM products
      WHERE category_id = $1
    `;

    const result = await db.query(queryText, [categoryId]);

    // Check for products in the Category
    if (result.rows.length === 0) {
      res.status(404).json({ message: "No products in this category"});
    }

    res.json(result.rows);

  } catch (error) {
    res.status(500).json({ message: "Error fetching products for this category", error: error.message });
  }
});

//
//Products
//

/**
 * @swagger
 * /products:
 *   get:
 *     summary: Get all products
 *     tags: [products]
 *     responses:
 *       200:
 *         description: A list of products
 */

app.get('/products', async (req, res, next) => {
  try {
    const queryText = `
      SELECT *
      FROM products
    `;
    
    const result = await db.query(queryText);
    
    res.json(result.rows);

  } catch (error) {
    res.status(500).json({ message: "Error fetching products", error: error.message });
  }
});

/**
 * @swagger
 * /products/{productId}:
 *   get:
 *     summary: Get product by ID
 *     tags: [products]
 *     parameters:
 *       - in: path
 *         name: productId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Product details
 *       404:
 *         description: Product not found
 */

app.get('/products/:productId', async (req, res, next) => {
  try {
    const queryText = `
      SELECT *
      FROM products
      WHERE id = $1
    `;

    const result = await db.query(queryText, [req.params.productId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json(result.rows[0]);

  } catch (error) {
   res.status(500).json({ message: "Error fetching product", error: error.message }); 
  }
});

//
//Order Section
//


// Lets you see Orders
/**
 * @swagger
 * /orders:
 *   get:
 *     summary: Lets you see previous Orders
 *     tags: [orders]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Orders found
 */

app.get('/orders', authenticateToken, async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        id,
        order_date,
        order_status
      FROM orders
      WHERE customer_id = $1 
      ORDER BY order_date DESC
    `;

    const result = await db.query(queryText, [req.user.id]);
    
    if (result.rows.length === 0) {
      return res.status(200).json({message:"You haven't placed any orders yet."});
    }

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "Error fetching order history", error: error.message });
  }
});


//Lets you see what is in an Order

/**
 * @swagger
 * /orders/{orderId}:
 *   get:
 *     summary: Lets you see what is in an Order
 *     tags: [orders]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: orderId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Order found
 */

app.get('/orders/:orderId', authenticateToken, async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        orderitems.quantity, 
        orderitems.price_at_purchase, 
        products.product_name 
      FROM orderitems
      JOIN products ON orderitems.product_id = products.id
      JOIN orders ON orderitems.order_id = orders.id
      WHERE orderitems.order_id = $1 AND orders.customer_id = $2
    `;
    
    const result = await db.query(queryText, [req.params.orderId, req.user.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Order not found or access denied" });
    }

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "Error fetching order details", error: error.message });
  }
});

// Cart
/**
 * @swagger
 * /cart:
 *   post:
 *     summary: Add an item to the cart
 *     tags: [cart]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               product_id: { type: integer }
 *               quantity: { type: integer }
 *             example:
 *               product_id: 1
 *               quantity: 2
 *     responses:
 *       200:
 *         description: Item added or quantity updated
 *       400:
 *         description: Not enough stock
 *       404:
 *         description: Product not found
 */

app.post('/cart', authenticateToken, async (req, res, next) => {
  try {
    const { product_id, quantity } = req.body;
    const customer_id = req.user.id;

    // 1. Check if the product exists and has enough stock
    const products = await db.query('SELECT stock_quantity FROM products WHERE id = $1', [product_id]);
    
    if (products.rows.length === 0) {
      return res.status(404).json({ message: "Product not found"});
    }

    if (products.rows[0].stock_quantity < quantity) {
      return res.status(400).json({ message: "Not enough stock"});
    }

    // 2. Logic: Check if this item is already in the cart for this user
    // This is why the cart_items table was created
    const checkCart = await db.query(
      'SELECT * FROM cart_items WHERE customer_id = $1 AND product_id = $2',
      [customer_id, product_id]
    );

    if (checkCart.rows.length > 0) {
      const updatedCart = await db.query(
        'UPDATE cart_items SET quantity = quantity + $1 WHERE customer_id = $2 AND product_id = $3 RETURNING *',
        [quantity, customer_id, product_id]
      );
      return res.json(updatedCart.rows[0]);
    }

    // 3. If it's a new item, insert it
      const newItem = await db.query(
        'INSERT INTO cart_items (customer_id, product_id, quantity) VALUES ($1, $2, $3) ON CONFLICT (customer_id, product_id) DO UPDATE SET quantity = cart_items.quantity + $3 RETURNING *',
        [customer_id, product_id, quantity]
      );

      res.status(201).json(newItem.rows[0]);

  } catch (error) {
    res.status(500).json({ message: "Error adding to cart", error: error.message });
  }
});

/**
 * @swagger
 * /cart:
 *   get:
 *     summary: View current user's cart
 *     tags: [cart]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of cart items
 */

app.get('/cart', authenticateToken, async (req, res, next) => {
  try {
    const queryText = `
      SELECT 
        c.id as cart_item_id, 
        p.product_name, 
        p.price, 
        c.quantity, 
        (p.price * c.quantity) AS subtotal
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.customer_id = $1
    `;
    const result = await db.query(queryText, [req.user.id]);
    res.json(result.rows);

  } catch (error) {
    res.status(500).json({ message: "Error fetching cart", error: error.message });
  }
});

/**
 * @swagger
 * /cart:
 *   delete:
 *     summary: Clear out the cart
 *     tags: [cart]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Cart cleared succesfully
 */


app.delete('/cart', authenticateToken, async (req, res, next) => {
  try {
    const result = await db.query('DELETE FROM cart_items WHERE customer_id = $1 RETURNING *', [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(200).json({ message: "Cart was already empty." });
    }

    res.json({ message: "Cart cleared succesfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting the cart", error: error.message });
  }
});

/**
 * @swagger
 * /cart/{itemId}:
 *   delete:
 *     summary: Remove an item from the cart
 *     tags: [cart]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: itemId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Item removed
 */

app.delete('/cart/:itemId', authenticateToken, async (req, res, next) => {
  try {
    await db.query('DELETE FROM cart_items WHERE id = $1 AND customer_id = $2', [req.params.itemId, req.user.id]);
    res.json({ message: "Item removed from cart" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting item from the cart", error: error.message });
  }
});

//Checkout route (involves Payments table)
//Lets the user process their order

/**
 * @swagger
 * /checkout:
 *   post:
 *     summary: Checkout items from the cart
 *     tags: [checkout]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Checkout succesfull
 */

app.post('/checkout', authenticateToken, async (req, res, next) => {

  const customer_id = req.user.id;

  try {
    await db.query('BEGIN');

    // 2. Get all items in the user's cart
    const cartResult = await db.query(
      'SELECT c.product_id, c.quantity, p.price, p.stock_quantity FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.customer_id = $1',
      [customer_id]
    );

    if (cartResult.rows.length === 0) {
      await db.query('ROLLBACK');
      return res.status(400).json({ message: "No items in your cart" });
    }

    // 3. Create the Order entry
    const orderResult = await db.query(
      'INSERT INTO orders (customer_id, order_date, order_status) VALUES ($1, NOW(), $2) RETURNING id', 
      [customer_id, 'completed']
    );
    const orderId = orderResult.rows[0].id;

    let totalAmount = 0;

    // 4. Process each item
    for (const item of cartResult.rows) {
      if (item.stock_quantity < item.quantity) {
        throw new Error(`Not enough stock for product with ID ${item.product_id}`);
      }
    
      // Subtract stock from Products table

      await db.query(
        'UPDATE products SET stock_quantity = stock_quantity - $1 WHERE id = $2',
        [item.quantity, item.product_id]
      );

    // Add to OrderItems table
      await db.query('INSERT INTO orderitems (order_id, product_id, quantity, price_at_purchase) VALUES ($1, $2, $3, $4)',
        [orderId, item.product_id, item.quantity, item.price]
      );

      totalAmount += item.price * item.quantity;
    }

    // 5. Create Payment record
    await db.query('INSERT INTO payments (order_id, payment_date, payment_amount, payment_method, payment_status) VALUES ($1, NOW(), $2, $3, $4)',
    [orderId, totalAmount, 'Credit Card', 'Success']
    );

    // 6. Clear the User's Cart
    await db.query('DELETE FROM cart_items WHERE customer_id = $1', [customer_id]);

    // 7. If everything succeeded, Commit to the database
    await db.query('COMMIT');

    res.status(201).json({ message: "Checkout Complete!", orderId: orderId });

  } catch(error) {
    await db.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  }
});