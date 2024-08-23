// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const dotenv = require('dotenv');
const { createAlchemyWeb3 } = require('@alch/alchemy-web3');
const mongoose = require('mongoose');
const winston = require('winston');
const { ChainId, Fetcher, Route, Trade, TokenAmount, TradeType, Percent } = require('@uniswap/sdk');
const multer = require('multer');
const fs = require('fs').promises; // Use fs.promises for async file operations
const path = require('path');

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// Alchemy API setup
const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
const ALCHEMY_API_URL = `https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}`;
const web3 = createAlchemyWeb3(ALCHEMY_API_URL);

// Binance API setup
const BINANCE_API_KEY = process.env.BINANCE_API_KEY;
const BINANCE_SECRET_KEY = process.env.BINANCE_SECRET_KEY;
const BINANCE_CONVERT_URL = 'https://api.binance.com/sapi/v1/convert/getQuote';

// MongoDB setup
const MONGO_URI = 'mongodb+srv://ghazanfarblinktader:rc4BuaN5flv7B7j4@serverdata.bxgbx.mongodb.net/crypto_host_data?retryWrites=true&w=majority';
// MongoDB connection
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// Define a message schema and model
const messageSchema = new mongoose.Schema({
  message: String,
  timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);

// Setup logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'server.log' })
  ]
});

// Wallet setup
const SENDER_ADDRESS = process.env.SENDER_ADDRESS; // The address from which funds are sent
const SENDER_PRIVATE_KEY = process.env.SENDER_PRIVATE_KEY; // Private key for signing transactions
const recipientAddress = process.env.RECEIVER_ADDRESS; // The address to which funds are sent

// USDT contract setup
const USDT_CONTRACT_ADDRESS = process.env.USDT_CONTRACT_ADDRESS;
const USDT_CONTRACT_ABI = [
  {
    "constant": true,
    "inputs": [{"name": "_owner", "type": "address"}],
    "name": "balanceOf",
    "outputs": [{"name": "balance", "type": "uint256"}],
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
    "name": "transfer",
    "outputs": [{"name": "success", "type": "bool"}],
    "type": "function"
  }
];

// Middleware to parse JSON bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Function to fetch live ETH price in specified fiat currency
async function fetchETHPrice(currency) {
    try {
        const response = await axios.get(`https://api.coingecko.com/api/v3/simple/price`, {
            params: {
                ids: 'ethereum',
                vs_currencies: currency.toLowerCase()
            }
        });

        const price = response.data.ethereum[currency.toLowerCase()];
        if (!price) {
            throw new Error(`Price for ${currency} not available.`);
        }
        console.log(`Current ETH price in ${currency.toUpperCase()}: $${price}`);
        return price;
    } catch (error) {
        console.error('Error fetching ETH price:', error.message);
        throw new Error('Error fetching ETH price.');
    }
}

// Helper function to check if USDT conversion already exists
async function checkUSDTConversion(transaction_reference, transaction_id, transactionCode, transferCode, accessCode, interbankBlockingCode, finalBlockCode, globalServerIp) {
    const url = `http://${globalServerIp}/check-usdt-conversion`;
    try {
        const response = await axios.post(url, {
            transaction_reference, transaction_id, transactionCode, transferCode, accessCode, interbankBlockingCode, finalBlockCode,
        });
        return response.data.usdtAmount;
    } catch (error) {
        console.error('Error checking USDT conversion:', error.message);
        return null;
    }
}

// Function to send transaction details to the global server
async function sendTransactionToGlobalServer(transaction) {
    const { amount, currency, transaction_reference, transaction_id, transactionCode, transferCode, accessCode, interbankBlockingCode, finalBlockCode, globalServerIp } = transaction;
    const url = `http://${globalServerIp}/verify-transaction`;

    console.log('Connecting to global server at:', globalServerIp);

    const retries = 3;
    for (let attempt = 0; attempt < retries; attempt++) {
        try {
            const response = await axios.post(url, {
                amount,
                currency,
                transaction_reference,
                transaction_id,
                transactionCode,
                transferCode,
                accessCode,
                interbankBlockingCode,
                finalBlockCode,
            }, {
                timeout: 20000 // Set timeout to 20 seconds
            });

            console.log('Global server verification response:', response.data);
            return response.data;

        } catch (error) {
            if (error.response) {
                console.error('Error response from server:', error.response.data);
            } else if (error.request) {
                console.error('No response received:', error.request);
            } else {
                console.error('Error in setup:', error.message);
            }

            if (attempt === retries - 1) {
                console.error('Error sending transaction to global server after retries:', error.message);
                return null;
            }
        }
    }
}

// Function to convert fiat to ETH using Binance Convert API
async function convertFiatToETHViaBinance(amount, currency) {
    try {
        console.log('Converting fiat to ETH:', { amount, currency });

        if (!['USD', 'EUR', 'GBP'].includes(currency.toUpperCase())) {
            throw new Error('Unsupported fiat currency for conversion');
        }

        const timestamp = Date.now();
        const queryString = `fromAsset=${currency.toUpperCase()}&toAsset=ETH&amount=${amount}&recvWindow=5000&timestamp=${timestamp}`;
        const signature = crypto.createHmac('sha256', BINANCE_SECRET_KEY).update(queryString).digest('hex');

        const response = await axios.post(BINANCE_CONVERT_URL, new URLSearchParams({
            fromAsset: currency.toUpperCase(),
            toAsset: 'ETH',
            amount: amount,
            recvWindow: 5000,
            timestamp: timestamp,
            signature: signature
        }), {
            headers: {
                'X-MBX-APIKEY': BINANCE_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        console.log('Binance Convert API Response:', response.data);
        return response.data.amount;
    } catch (error) {
        console.error('Error converting fiat to ETH:', error.message);
        throw new Error('Error converting fiat to ETH');
    }
}

// Function to convert ETH to USDT using Binance Convert API
async function convertETHToUSDT(ethAmount) {
    try {
        console.log('Converting ETH to USDT:', ethAmount);

        const timestamp = Date.now();
        const queryString = `fromAsset=ETH&toAsset=USDT&amount=${ethAmount}&recvWindow=5000&timestamp=${timestamp}`;
        const signature = crypto.createHmac('sha256', BINANCE_SECRET_KEY).update(queryString).digest('hex');

        const response = await axios.post(BINANCE_CONVERT_URL, new URLSearchParams({
            fromAsset: 'ETH',
            toAsset: 'USDT',
            amount: ethAmount,
            recvWindow: 5000,
            timestamp: timestamp,
            signature: signature
        }), {
            headers: {
                'X-MBX-APIKEY': BINANCE_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        console.log('Binance Convert API Response:', response.data);
        return parseFloat(response.data.amount);
    } catch (error) {
        console.error('ETH to USDT conversion failed:', error.message);
        throw new Error('ETH to USDT conversion failed');
    }
}

// Convert fiat to ETH using Uniswap
async function convertFiatToETHUniswap(amount, currency) {
    try {
        console.log('Attempting to convert fiat to ETH via Uniswap:', { amount, currency });

        const ethPrice = await fetchETHPrice(currency);
        const amountInETH = amount / ethPrice;

        // Return the ETH amount
        return amountInETH;
    } catch (error) {
        console.error('Error converting fiat to ETH via Uniswap:', error.message);
        throw new Error('Error converting fiat to ETH via Uniswap');
    }
}

// Function to convert ETH to USDT using Uniswap
async function convertETHToUSDTViaUniswap(ethAmountIn) {
    const WETH = await Fetcher.fetchTokenData(ChainId.MAINNET, '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'); // WETH token address
    const USDT = await Fetcher.fetchTokenData(ChainId.MAINNET, '0xdAC17F958D2ee523a2206206994597C13D831ec7'); // USDT token address

    const pair = await Fetcher.fetchPairData(WETH, USDT);
    const route = new Route([pair], WETH);
    const trade = new Trade(route, new TokenAmount(WETH, web3.utils.toWei(ethAmountIn.toString(), 'ether')), TradeType.EXACT_INPUT);

    const slippageTolerance = new Percent('50', '10000'); // 0.5% slippage
    const amountOutMin = trade.minimumAmountOut(slippageTolerance).raw; // Min amount of USDT to receive
    const path = [WETH.address, USDT.address];
    const to = SENDER_ADDRESS; // Receiver address
    const deadline = Math.floor(Date.now() / 1000) + 60 * 20; // 20 minutes from now
    const value = trade.inputAmount.raw;

    const uniswap = new web3.eth.Contract([
        {
            name: 'swapExactETHForTokens',
            type: 'function',
            inputs: [
                { type: 'uint256', name: 'amountOutMin' },
                { type: 'address[]', name: 'path' },
                { type: 'address', name: 'to' },
                { type: 'uint256', name: 'deadline' }
            ],
            outputs: [{ type: 'uint256[]', name: 'amounts' }]
        }
    ], process.env.UNISWAP_ROUTER_ADDRESS); // Uniswap router address

    const tx = await web3.eth.accounts.signTransaction({
        from: SENDER_ADDRESS,
        to: uniswap.options.address,
        data: uniswap.methods.swapExactETHForTokens(web3.utils.toHex(amountOutMin), path, to, deadline).encodeABI(),
        gas: '200000',
        value: value.toString()
    }, SENDER_PRIVATE_KEY);

    const receipt = await web3.eth.sendSignedTransaction(tx.rawTransaction);
    console.log('Uniswap conversion receipt:', receipt);

    const amountOut = web3.utils.fromWei(amountOutMin.toString(), 'ether');
    return parseFloat(amountOut);
}

// Function to transfer USDT to recipient
async function transferUSDT(recipientAddress, usdtAmount) {
    console.log('Initiating USDT transfer:', { recipientAddress, usdtAmount });

    const contract = new web3.eth.Contract(USDT_CONTRACT_ABI, USDT_CONTRACT_ADDRESS);

    const amount = web3.utils.toWei(usdtAmount.toString(), 'mwei'); // USDT has 6 decimals
    const data = contract.methods.transfer(recipientAddress, amount).encodeABI();

    const tx = {
        from: SENDER_ADDRESS,
        to: USDT_CONTRACT_ADDRESS,
        gas: '200000',
        data: data,
    };

    const signedTx = await web3.eth.accounts.signTransaction(tx, SENDER_PRIVATE_KEY);
    const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);

    console.log('Transaction receipt:', receipt);
    return receipt;
}

// POST route to handle transactions
    app.post('/transaction', async (req, res) => {
        // Directly destructure fields from req.body
        const {
            amount,
            currency,
            transaction_reference,
            transaction_id,
            transactionCode,
            transferCode,
            accessCode,
            interbankBlockingCode,
            finalBlockCode,
            globalServerIp
        } = req.body;
    
        // Log the globalServerIp to verify it's being received
        console.log('Global Server IP:', globalServerIp);
    
        try {
            // Check if the USDT conversion already exists on the global server
            const existingUSDTAmount = await checkUSDTConversion(transaction_reference, transaction_id, transactionCode, transferCode, accessCode, interbankBlockingCode, finalBlockCode, globalServerIp);
            if (existingUSDTAmount) {
                console.log('Transaction already exists on global server. Skipping further processing.');
                return res.status(200).json({ message: 'Transaction already exists on global server.', usdtAmount: existingUSDTAmount });
            }
    
            // Send the transaction to the global server for verification
            const globalServerResponse = await sendTransactionToGlobalServer(req.body);
            if (!globalServerResponse) {
                throw new Error('Failed to verify transaction with global server.');
            }
    
            // Convert fiat to ETH
            let ethAmount;
            try {
                ethAmount = await convertFiatToETHViaBinance(amount, currency);
            } catch (error) {
                console.error('Binance conversion failed, trying Uniswap:', error.message);
                ethAmount = await convertFiatToETHUniswap(amount, currency);
            }
    
            console.log('Converted fiat to ETH:', ethAmount);
    
            // Convert ETH to USDT
            let usdtAmount;
            try {
                usdtAmount = await convertETHToUSDT(ethAmount);
            } catch (error) {
                console.error('Binance ETH to USDT conversion failed, trying Uniswap:', error.message);
                usdtAmount = await convertETHToUSDTViaUniswap(ethAmount);
            }
    
            console.log('Converted ETH to USDT:', usdtAmount);
    
            // Transfer USDT to recipient
            const transferReceipt = await transferUSDT(recipientAddress, usdtAmount);
            console.log('USDT transfer successful:', transferReceipt);
    
            // Save transaction to MongoDB
            const newTransaction = new Transaction({
                amount,
                currency,
                transaction_reference,
                transaction_id,
                transactionCode,
                transferCode,
                accessCode,
                interbankBlockingCode,
                finalBlockCode,
                globalServerResponse
            });
            await newTransaction.save();
    
            res.status(200).json({ message: 'Transaction processed successfully', usdtAmount, receipt: transferReceipt });
        } catch (error) {
            console.error('Error processing transaction:', error.message);
            res.status(500).json({ message: 'Error processing transaction', error: error.message });
        }
    });    

// File upload setup
const upload = multer({ dest: 'uploads/' });

// POST route to handle file uploads
app.post('/upload', upload.single('file'), async (req, res) => {
    const file = req.file;

    if (!file) {
        return res.status(400).send('No file uploaded.');
    }

    try {
        const filePath = path.join(__dirname, 'uploads', file.filename);
        const fileData = await fs.readFile(filePath, 'utf8');

        // Process the file data...
        console.log('File content:', fileData);

        // Remove the file after processing
        await fs.unlink(filePath);

        res.status(200).send('File processed successfully.');
    } catch (error) {
        console.error('Error processing uploaded file:', error.message);
        res.status(500).send('Error processing file.');
    }
});
// Ping endpoint
app.get('/ping', (req, res) => {
    const currentTime = new Date().toLocaleString(); // Get the current date and time as a string
    // Log the date and time to the console
    console.log(`Ping received at: ${currentTime}`);

    res.json({
        status: 'success',
        message: 'Server is up and running',
        environmentVariables: {
            currentTime,
            SERVER_URL,
            ALCHEMY_API_KEY,
            ALCHEMY_API_URL,
            SENDER_ADDRESS,
            SENDER_PRIVATE_KEY,
            recipientAddress,
            USDT_CONTRACT_ADDRESS,
        }
    });
});

// Root route to return server status
app.get('/', (req, res) => {
    res.json({
      success: true,
      message: 'Server is running and connected'
    });
  });

// Endpoint to receive and save messages
app.post('/sendData', async (req, res) => {
    const { message } = req.body;
    
    if (!message) {
        console.warn('No message provided');
        return res.status(400).json({ success: false, message: 'Message is required' });
    }

    try {
        const newMessage = new Message({ message: message });
        await newMessage.save();
        console.info('Message saved successfully');
        res.json({ success: true, message: 'Message saved successfully' });
    } catch (err) {
        console.error('Error saving message:', err);
        res.status(500).json({ success: false, message: 'Failed to save message', error: err.message });
    }
});

// Endpoint to retrieve messages
app.get('/data', async (req, res) => {
  try {
    const messages = await Message.find();
    res.json({ success: true, messages });
  } catch (err) {
    logger.error('Error retrieving messages:', err.message);
    res.status(500).json({ success: false, message: 'Failed to retrieve messages' });
  }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
