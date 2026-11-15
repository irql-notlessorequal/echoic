// echoic, a recursive DNS resolver.
// Copyright (C) IRQL_NOT_LESS_OR_EQUAL
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use hickory_server::proto::op::Message;

/// Returns true when an answer or authority record carries a bogus DNSSEC proof.
///
/// Additional-section records are excluded because a bogus record
/// there is dropped from the response instead of failing the whole exchange.
pub(crate) fn message_is_bogus(message: &Message) -> bool {
    message
        .answers
        .iter()
        .chain(message.authorities.iter())
        .any(|record| record.proof.is_bogus())
}
