from infosecwriteups.database import ThreatDatabase

if __name__ == '__main__':
    db = ThreatDatabase()

    print('Total rows (no filter):')
    all_rows = db.get_all_threats()
    print(len(all_rows))

    print('\nRows with threat_score >= 50:')
    high = db.query_threats(min_score=50)
    print(len(high))
    for row in high[:5]:
        print(row)

    print('\nRows classified as Malicious:')
    mal = db.query_threats(classification='Malicious')
    print(len(mal))
    for row in mal[:5]:
        print(row)
