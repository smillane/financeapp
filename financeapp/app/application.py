import os

from app import app
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from app.helpers import apology, login_required, lookup, usd

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///app/finance.db")


@app.route("/")
@login_required
def index():
    portfolio = db.execute("SELECT symbol, quantity FROM portfolios WHERE user_id = :user_id ORDER BY symbol ASC",
            user_id = session["user_id"])

    cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                user_id = session["user_id"])[0]["cash"]

    if not portfolio:
        return render_template("index.html", cash = usd(cash), value = (usd(cash)))

    total = 0

    for stocks in portfolio:
        name = price = lookup(stocks["symbol"])["name"]
        stocks.update({ "name": name })

        price =lookup(stocks["symbol"])["price"]
        stocks.update({ "price": usd(price) })

        value = price * stocks["quantity"]
        stocks.update({ "value": usd(value) })

        total = total + value

    total = total + cash

    return render_template("index.html", portfolio = portfolio, cash = usd(cash), value = usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":

        input_symbol = request.form.get("symbol")

        input_symbol = input_symbol.upper()

        input_quantity = request.form.get("quantity")

        if not input_symbol:
            return apology("Enter Ticker", 400)

        if not lookup(input_symbol):
            return apology("Invalid Ticker", 400)

        elif not input_quantity.isdigit() or int(input_quantity) < 1:
            return apology("Invalid quantity", 400)

        price = lookup(input_symbol)["price"]

        transaction = price * int(input_quantity)

        user_balance = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])[0]["cash"]

        if transaction > user_balance:
            return apology("Insufficient funds", 400)

        db.execute("INSERT INTO transactions(user_id, type, symbol, quantity, price) VALUES (:user_id, :transaction_type, :symbol, :quantity, :price)",
            user_id = session["user_id"],
            transaction_type = "purchase",
            symbol = input_symbol,
            quantity = int(input_quantity),
            price = format(transaction, '0.2f'))

        user_balance = user_balance - transaction

        db.execute("UPDATE users SET cash = :balance WHERE id = :user_id",
            user_id = session["user_id"],
            balance = user_balance)

        portfolio = db.execute("SELECT quantity FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
            user_id = session["user_id"],
            symbol = input_symbol)

        if len(portfolio) == 1:
            quantity = portfolio[0]["quantity"] + int(input_quantity)

            db.execute("UPDATE portfolios SET quantity = :quantity WHERE user_id = :user_id AND symbol = :symbol",
                user_id = session["user_id"],
                symbol = input_symbol,
                quantity = quantity)

        else:
            db.execute("INSERT INTO portfolios (user_id, symbol, quantity) VALUES (:user_id, :symbol, :quantity)",
                user_id = session["user_id"],
                symbol = input_symbol,
                quantity = int(input_quantity))

        if int(input_quantity) == 1:
            flash(f"Bought {input_quantity} Share of {input_symbol} at {price} per share")

        else:
            flash(f"Bought {input_quantity} Shares of {input_symbol} at {price} per share")

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    history = db.execute("SELECT date, type, symbol, quantity, price FROM transactions WHERE user_id = :user_id ORDER BY id DESC",
            user_id = session["user_id"])

    if not history:
        return render_template("history.html")

    for transaction in history:
        date = transaction["date"]
        transaction.update({ "date": date })

        transaction_type = transaction["type"]
        transaction.update({ "type": transaction_type })

        symbol = transaction["symbol"]
        transaction.update({ "symbol": symbol })

        quantity = transaction["quantity"]
        transaction.update({ "quantity": quantity })

        price = transaction["price"]
        transaction.update({ "price": price })

    total = len(history)

    return render_template("history.html", history = history, total = total)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/trade", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        input_symbol = request.form.get("symbol")

        input_symbol = input_symbol.upper()

        if not input_symbol:
            return apology("Enter Ticker", 400)

        if not lookup(input_symbol):
            return apology("Invalid Ticker", 400)

        quote = lookup(input_symbol)

        quote["price"] = usd(quote["price"])

        portfolio = db.execute("SELECT quantity FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
            user_id = session["user_id"],
            symbol = input_symbol)

        cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
            user_id = session["user_id"])[0]["cash"]

        if not portfolio:
            return render_template("trading.html", quote = quote, cash = usd(cash))

        return render_template("trading.html", quote = quote, portfolio = portfolio, cash = usd(cash))

    else:
        return render_template("trade.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        register_username = request.form.get("username")
        register_password = request.form.get("password")
        register_password_check = request.form.get("password_check")

        if not request.form.get("username"):
            return apology("Must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide password", 403)

        elif not request.form.get("password_check"):
            return apology("Must provide password", 403)

        elif not register_password == register_password_check:
            return apology("Passwords must match", 403)

        # Query database for username
        username = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        if len(username) == 1:
            return apology("Username already taken")

        # hash password
        else:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
            username = register_username, password = generate_password_hash(register_password, method="pbkdf2:sha256", salt_length=8))

            if new_user:
                # Remember which user has logged in
                session["user_id"] = new_user

            flash(f"You've registered an account!")

            # Redirect user to home page
            return redirect("/")

    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":

        input_symbol = request.form.get("symbol")

        input_symbol = input_symbol.upper()

        input_quantity = request.form.get("quantity")

        if not input_symbol:
            return apology("Enter Ticker", 400)

        if not lookup(input_symbol):
            return apology("Invalid Ticker", 400)

        elif not input_quantity.isdigit() or int(input_quantity) < 1:
            return apology("Invalid quantity", 400)

        price = lookup(input_symbol)["price"]

        transaction = price * int(input_quantity)

        user_quantity = db.execute("SELECT quantity FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
        user_id = session["user_id"],
        symbol = input_symbol)

        if len(user_quantity) != 1 or user_quantity[0]["quantity"] < int(input_quantity):
            return apology("Not enough shares", 400)

        user_balance = db.execute("SELECT cash FROM users WHERE id = :user_id",
        user_id = session["user_id"])[0]["cash"]

        db.execute("INSERT INTO transactions(user_id, type, symbol, quantity, price) VALUES (:user_id, :transaction_type, :symbol, :quantity, :price)",
            user_id = session["user_id"],
            transaction_type = "sell",
            symbol = input_symbol,
            quantity = int(input_quantity),
            price = format(transaction, '0.2f'))

        user_balance = user_balance + transaction

        db.execute("UPDATE users SET cash = :balance WHERE id = :user_id",
            user_id = session["user_id"],
            balance = user_balance)

        user_quantity = user_quantity[0]["quantity"] - int(input_quantity)

        if user_quantity == 0:
            db.execute("DELETE FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
                user_id = session["user_id"],
                symbol = input_symbol)

        else:
            db.execute("UPDATE portfolios SET quantity = :quantity WHERE user_id = :user_id AND symbol = :symbol",
                user_id = session["user_id"],
                symbol = input_symbol,
                quantity = user_quantity)

        if int(input_quantity) == 1:
            flash(f"Sold {input_quantity} Share of {input_symbol} at {price} per share")

        else:
            flash(f"Sold {input_quantity} Shares of {input_symbol} at {price} per share")

        return redirect("/")

    else:
        return render_template("sell.html")

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":

        # Ensure username was submitted
        username = request.form.get("username")
        new_password = request.form.get("new_password")
        new_password_check = request.form.get("new_password_check")

        if not request.form.get("username"):
            return apology("Must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("new_password"):
            return apology("Must provide new password", 403)

        elif not request.form.get("new_password_check"):
            return apology("Must provide new password", 403)

        elif not new_password == new_password_check:
            return apology("Passwords must match", 403)

        db.execute("UPDATE users SET hash = :password WHERE username = :username",
        username = username, password = generate_password_hash(new_password, method="pbkdf2:sha256", salt_length=8))

        flash(f"Your password has been changed!")

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("settings.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)