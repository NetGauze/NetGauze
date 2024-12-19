Cloned from the crate [`nom_locate`](https://github.com/fflorent/nom_locate) but with the omission of computing
the line & column number since we don't care about them in binary protocols,
and they do make using the `LocateSpan` slower.