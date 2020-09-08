package test

type MockDb struct {
}

func (db *MockDb) InitDatabase() error {
	panic("implement me")
}

func (db *MockDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {

	return nil
}

func (db *MockDb) ReadData(data interface{}, cols ...string) (err error) {
	return nil
}

func (db *MockDb) DeleteData(data interface{}, cols ...string) (err error) {
	return nil
}

func (db *MockDb) QueryCount(tableName string) (int64, error) {
	return 0, nil
}

func (db *MockDb) QueryCountForAppInfo(tableName, fieldName, fieldValue string) (int64, error) {
	return 0, nil
}
