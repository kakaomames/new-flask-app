import os
from flask import Flask, request, render_template, redirect, url_for

# Flaskアプリケーションのインスタンスを作成
app = Flask(__name__)

# アップロードされたファイルを保存するディレクトリ
# Renderでは一時的なストレージが提供されるため、そこに保存します
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER) # ディレクトリが存在しない場合のみ作成
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 許可するファイルの種類 (APKファイルのみ)
ALLOWED_EXTENSIONS = {'apk', 'apks'}

# ファイルが許可された拡張子を持つかチェックする関数
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ウェブインターフェースのルート ---

@app.route('/')
def index():
    """
    ファイルのアップロードフォームを表示するページ。
    """
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_apk():
    """
    アップロードされたAPKファイルを受け取り、保存するエンドポイント。
    """
    # ファイルがリクエストに含まれているか確認
    if 'file' not in request.files:
        return "ファイルがアップロードされていません。", 400

    file = request.files['file']

    # ファイル名が空の場合（ファイルが選択されなかった場合）
    if file.filename == '':
        return "ファイルが選択されていません。", 400

    # ファイルが許可された種類であり、存在する場合
    if file and allowed_file(file.filename):
        # ファイル名を安全にする（パスインジェクション対策）
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # ここで、保存されたAPKファイル (filepath) を次の解析ステップに渡します
        # 今は単に成功メッセージを表示するだけですが、後でリダイレクトなどに変更します
        return f"ファイル '{filename}' を正常に受け取りました。解析を開始します。", 200
    else:
        return "許可されていないファイル形式です。APKまたはAPKSファイルをアップロードしてください。", 400

# アプリケーションを実行する際の定型コード
if __name__ == '__main__':
    # デバッグモードは開発中のみ有効にし、本番環境では無効にしてください
    app.run(debug=True)
