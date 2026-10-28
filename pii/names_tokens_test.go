package pii

import "testing"

// locksql#18: logins, handles and bare mail columns are personal data; free
// text and coordinates are quasi-identifiers the human decides about.
func TestLooksPersonalLoginsAndMail(t *testing.T) {
	for _, n := range []string{"mail", "e_mail", "e-mail", "E-Mail", "login", "username", "userName", "nickname",
		"pseudo", "handle", "twitter_handle", "displayname", "display_name", "adminusername", "customer_mail"} {
		if !LooksPersonal(n) {
			t.Errorf("%s: not personal", n)
		}
	}
	for _, n := range []string{"mail_id", "login_count", "username_verified", "e_mail_id", "template_name", "file_name"} {
		if LooksPersonal(n) {
			t.Errorf("%s: personal", n)
		}
	}
	// last_login is a timestamp (Django's auth_user.last_login), not a login.
	if LooksPersonalColumn("last_login", "timestamp with time zone") || LooksPersonalColumn("login", "datetime") {
		t.Error("a temporal login column is personal")
	}
	if !LooksPersonalColumn("login", "varchar(150)") {
		t.Error("login varchar: not personal")
	}
}

func TestLooksQuasiFreeTextAndCoordinates(t *testing.T) {
	for _, n := range []string{"notes", "note", "comment", "comments", "bio", "remarks", "commentaire", "opmerking",
		"lat", "lng", "lon", "latitude", "longitude", "geo_lat", "gps_coordinates"} {
		if !LooksQuasi(n) {
			t.Errorf("%s: not quasi", n)
		}
		if LooksPersonal(n) {
			t.Errorf("%s: personal, want quasi only", n)
		}
	}
	for _, n := range []string{"comment_count", "notes_count", "lat_id", "description", "long"} {
		if LooksQuasi(n) {
			t.Errorf("%s: quasi", n)
		}
	}
}
