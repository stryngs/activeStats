# activeStats
Creates actionable statistics based on the following characteristics of Active Directory:
  - No password expiration
  - Password not required
  - Expired password
  - Account has not been logged in within the last 90 days

## Environment prep
```
git clone https://github.com/stryngs/officeTasks
python3 -m pip install officeTasks/officeTasks-*
python3 -m pip install -r requirements.txt
```

## Example usage
```
powershell .\get-boxes.ps1
powershell .\get-users.ps1
python .\activeStats.py
```
