import pandas as pd
from flask import Flask, jsonify
from collections import defaultdict

#load data
data = pd.read_csv(f'/vuln2.csv')

# create group vulnerabilities
def group_vulnerabilities(data):
    grouped = defaultdict(list)
    tag_counter = 1
    for _, row in data.iterrows():
        key = (row['endpoint'], row['cve'])
        grouped[key].append(row.to_dict())

    # Find tags
    result = []
    for group, items in grouped.items():
        tag = f"group_{tag_counter}"
        for item in items:
            item['tag'] = tag
            result.append(item)
        tag_counter += 1

    return result


# create API
app = Flask(__name__)


@app.route('/vulnerabilities/', methods=['GET'])
def vulnerabilities():
    grouped_data = group_vulnerabilities(data)
    return jsonify(grouped_data)


if __name__ == '__main__':
    app.run(debug=True)
