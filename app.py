import os
import zipfile
import shutil # ディレクトリ削除のために追加
import json   # JSON出力のために追加

from flask import Flask, request, render_template, redirect, url_for, jsonify
from werkzeug.utils import secure_filename

# androguardのインポート
from androguard.decompiler.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

# Flaskアプリケーションのインスタンスを作成
app = Flask(__name__)

# アップロードされたファイルを保存するディレクトリ
UPLOAD_FOLDER = 'uploads'
# 解凍されたファイルを保存するディレクトリ
EXTRACT_FOLDER = 'extracted'
# 解析結果を保存するディレクトリ
ANALYSIS_RESULTS_FOLDER = 'analysis_results'

# ディレクトリが存在しない場合は作成
for folder in [UPLOAD_FOLDER, EXTRACT_FOLDER, ANALYSIS_RESULTS_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['EXTRACT_FOLDER'] = EXTRACT_FOLDER
app.config['ANALYSIS_RESULTS_FOLDER'] = ANALYSIS_RESULTS_FOLDER

# 許可するファイルの種類 (APKファイルのみ)
ALLOWED_EXTENSIONS = {'apk', 'apks'}

# ファイルが許可された拡張子を持つかチェックする関数
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ヘルパー関数: APKファイルを解凍する ---
def extract_apk(apk_filepath):
    """
    指定されたAPKファイルを解凍し、解凍されたディレクトリのパスを返す。
    APKがAPKS形式の場合（ZIP内に複数の.apkファイルが含まれる場合）も対応。
    """
    base_filename = os.path.splitext(os.path.basename(apk_filepath))[0]
    extraction_target_dir = os.path.join(app.config['EXTRACT_FOLDER'], f"{base_filename}_extracted")

    if os.path.exists(extraction_target_dir):
        shutil.rmtree(extraction_target_dir) # 既存のディレクトリを削除
    os.makedirs(extraction_target_dir)

    try:
        with zipfile.ZipFile(apk_filepath, 'r') as zip_ref:
            zip_ref.extractall(extraction_target_dir)
        print(f"APK '{apk_filepath}' を '{extraction_target_dir}' に解凍しました。")

        # APKSファイルの場合、内部に複数の.apkファイルが含まれる可能性があるので、それらも解凍する
        # ここでは簡易的に、抽出されたディレクトリ内の全ての.apkファイルをさらに解凍する
        # より堅牢なAPKS処理には、別途ツール(bundletoolなど)の使用が推奨されますが、
        # Pythonのみで簡易的に行う場合の一例です。
        for root, _, files in os.walk(extraction_target_dir):
            for file in files:
                if file.endswith('.apk'):
                    inner_apk_filepath = os.path.join(root, file)
                    inner_apk_base_name = os.path.splitext(file)[0]
                    inner_apk_extract_dir = os.path.join(root, f"{inner_apk_base_name}_extracted")
                    
                    if not os.path.exists(inner_apk_extract_dir):
                        os.makedirs(inner_apk_extract_dir)
                    
                    try:
                        with zipfile.ZipFile(inner_apk_filepath, 'r') as inner_zip_ref:
                            inner_zip_ref.extractall(inner_apk_extract_dir)
                        print(f"  内部APK '{inner_apk_filepath}' を '{inner_apk_extract_dir}' に解凍しました。")
                    except zipfile.BadZipFile:
                        print(f"  警告: '{inner_apk_filepath}' は不正なZIPファイルです。")
                    except Exception as e:
                        print(f"  内部APK '{inner_apk_filepath}' の解凍中にエラーが発生しました: {e}")

        return extraction_target_dir

    except zipfile.BadZipFile:
        print(f"エラー: '{apk_filepath}' は不正なZIPファイルです。")
        return None
    except Exception as e:
        print(f"APKの解凍中にエラーが発生しました: {e}")
        return None

# --- ヘルパー関数: APKコンテンツを解析する ---
def analyze_apk_content(apk_filepath, extracted_dir):
    """
    解凍されたAPKディレクトリ内のAndroidManifest.xml, classes.dex, .soファイルを解析し、
    結果を辞書形式で返す。
    """
    analysis_results = {
        "apk_name": os.path.basename(apk_filepath),
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "android_manifest": {},
        "dex_files": [],
        "native_libraries": [],
        "resource_files": [],
        "assets_files": [],
        "security_findings": [] # 今後追加
    }

    # APKファイルをandroguardでロード
    try:
        a = APK(apk_filepath)
        analysis_results["package_name"] = a.get_package()
        analysis_results["version_name"] = a.get_androidversionname()
        analysis_results["version_code"] = a.get_androidversioncode()
        analysis_results["min_sdk_version"] = a.get_min_sdk_version()
        analysis_results["target_sdk_version"] = a.get_target_sdk_version()

        # AndroidManifest.xmlの解析
        manifest_path = os.path.join(extracted_dir, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            analysis_results["android_manifest"] = {
                "file_name": "AndroidManifest.xml",
                "relative_path_in_extracted": "AndroidManifest.xml",
                "permissions": a.get_permissions(),
                "activities": a.get_activities(),
                "services": a.get_services(),
                "receivers": a.get_receivers(),
                "providers": a.get_providers(),
            }
        
        # classes.dexファイルの解析
        # androguardはAPKオブジェクトから直接DEXファイルにアクセスできる
        dex_files_in_apk = a.get_dex_names()
        for dex_name in dex_files_in_apk:
            dex_data = a.get_file(dex_name)
            d = DalvikVMFormat(dex_data)
            dx = Analysis(d)

            classes_count = len(d.get_classes())
            methods_count = len(d.get_methods())
            
            # 文字列の抽出 (簡易版)
            strings_extracted = []
            for s in d.get_strings():
                # 長すぎる文字列やバイナリデータはスキップ
                if 3 < len(s) < 200 and all(32 <= ord(c) <= 126 for c in s): # 簡易的な可視文字判定
                    strings_extracted.append(s)
            
            # URLの抽出 (簡易版: "http"または"https"を含む文字列)
            urls_found = [s for s in strings_extracted if "http://" in s or "https://" in s]

            analysis_results["dex_files"].append({
                "file_name": dex_name,
                "relative_path_in_extracted": dex_name, # APKルートからの相対パス
                "classes_count": classes_count,
                "methods_count": methods_count,
                "strings_extracted": strings_extracted[:50], # 例として最初の50個
                "urls_found": urls_found[:20] # 例として最初の20個
            })

        # .soファイルの解析 (簡易版: ファイルリストと文字列抽出)
        # androguardのAPKオブジェクトからget_files()で全てのファイルを取得し、.soをフィルタ
        for filename in a.get_files():
            if filename.endswith('.so'):
                so_data = a.get_file(filename)
                
                # .soファイル内の文字列を抽出 (androguardの機能ではないので、簡易的にバイナリから抽出)
                # より堅牢な文字列抽出には `strings` コマンドの実行や `elftools` が必要
                so_strings = []
                try:
                    # バイナリデータをデコード可能な文字列として扱う
                    decoded_so_data = so_data.decode('latin-1', errors='ignore')
                    # ASCII文字の連続を抽出する簡易的な方法
                    current_string = []
                    for char_code in so_data:
                        if 32 <= char_code <= 126: # 表示可能なASCII文字
                            current_string.append(chr(char_code))
                        else:
                            if len(current_string) >= 4: # 4文字以上の文字列を抽出
                                so_strings.append("".join(current_string))
                            current_string = []
                    if len(current_string) >= 4:
                        so_strings.append("".join(current_string))

                except Exception as e:
                    print(f"  .soファイル '{filename}' の文字列抽出中にエラー: {e}")
                
                # ABIの推測 (パスから)
                architecture = "unknown"
                if "arm64-v8a" in filename:
                    architecture = "arm64-v8a"
                elif "armeabi-v7a" in filename:
                    architecture = "armeabi-v7a"
                elif "x86_64" in filename:
                    architecture = "x86_64"
                elif "x86" in filename:
                    architecture = "x86"

                analysis_results["native_libraries"].append({
                    "file_name": os.path.basename(filename),
                    "relative_path_in_extracted": filename, # APKルートからの相対パス
                    "architecture": architecture,
                    "size_bytes": len(so_data),
                    "strings_extracted": so_strings[:50] # 例として最初の50個
                })
        
        # その他リソースファイル、アセットファイルのリストアップ (簡易版)
        for filename in a.get_files():
            if filename.startswith("res/") and not filename.endswith('.xml'): # XMLはマニフェストで処理済みとして簡易的に除外
                analysis_results["resource_files"].append({
                    "file_name": os.path.basename(filename),
                    "relative_path_in_extracted": filename,
                    "type": "resource"
                })
            elif filename.startswith("assets/"):
                analysis_results["assets_files"].append({
                    "file_name": os.path.basename(filename),
                    "relative_path_in_extracted": filename,
                    "type": "asset"
                })


    except Exception as e:
        print(f"APK解析中にエラーが発生しました: {e}")
        analysis_results["error"] = str(e)

    return analysis_results

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
    アップロードされたAPKファイルを受け取り、保存し、解凍し、解析するエンドポイント。
    """
    if 'file' not in request.files:
        return "ファイルがアップロードされていません。", 400

    file = request.files['file']

    if file.filename == '':
        return "ファイルが選択されていません。", 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # ファイルを保存した後、解凍処理を呼び出す
        extracted_dir = extract_apk(filepath)

        if extracted_dir:
            # 解凍後、解析処理を呼び出す
            analysis_data = analyze_apk_content(filepath, extracted_dir)
            
            # 解析結果をJSONファイルとして保存
            # 例: com_example_app.json
            output_filename_base = analysis_data.get("package_name", os.path.splitext(filename)[0]).replace('.', '_')
            output_json_filename = f"{output_filename_base}.json"
            output_json_filepath = os.path.join(app.config['ANALYSIS_RESULTS_FOLDER'], output_json_filename)
            
            with open(output_json_filepath, 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, ensure_ascii=False, indent=4)

            # 解析結果をJSONとして返す
            return jsonify(analysis_data), 200
        else:
            return f"ファイル '{filename}' の解凍に失敗しました。", 500
    else:
        return "許可されていないファイル形式です。APKまたはAPKSファイルをアップロードしてください。", 400

# アプリケーションを実行する際の定型コード
if __name__ == '__main__':
    app.run(debug=True)
