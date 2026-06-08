require('dotenv').config();
const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URI).then(async () => {
    console.log("Connected to DB...");

    // 1. Reset Users
    const User = mongoose.model('User', new mongoose.Schema({ used_today: Number }));
    await User.updateMany({}, { $set: { used_today: 0 } });

    // 2. Reset Worker Node Stats
    const NodeWorker = mongoose.model('NodeWorker', new mongoose.Schema({ used_today: Number, error_count: Number }));
    await NodeWorker.updateMany({}, { $set: { used_today: 0, error_count: 0 } });

    console.log("✅ Counters wiped! 'Used Today' is back to 0.");
    process.exit(0);
});
