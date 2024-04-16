from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def welcome():
    return f"""
    <html>
    <head>
        <title>Welcome to 2022!</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 50px;
            }}
            .container {{
                max-width: 600px;
                margin: auto;
                padding: 20px;
                border: 1px solid #ccc;
                border-radius: 5px;
                background-color: #f9f9f9;
            }}
            h1 {{
                color: #333;
                text-align: center;
            }}
            p {{
                color: #666;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to 2022!</h1>
        </div>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(debug=True)
